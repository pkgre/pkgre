#!/usr/bin/env python3
import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
WORK=ROOT.parent.parent
PROPOSAL=WORK/'d0-time-resource-proposal'
REPORT=ROOT/'REPORT.md'
OUT=ROOT/'validation.json'
FIXTURES=('timestamp-fixtures.json','shutdown-drain-fixtures.json','resource-limit-fixtures.json')
checks=[]
def check(name,condition,detail=None):
 checks.append({'name':name,'pass':bool(condition),'detail':detail})
 if not condition: raise AssertionError(f'{name}: {detail}')
def load(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def case_map(d): return {x['id']:x for x in d['cases']}
try:
 docs={name:load(ROOT/name) for name in FIXTURES}
 proposal=load(PROPOSAL/'proposal.json')
 proposal_validation=load(PROPOSAL/'validation.json')
 report=REPORT.read_text()
 check('json-document-count',len(docs)==3)
 expected_schemas={'timestamp-fixtures.json':'pkgre-d0-timestamp-fixtures-v1','shutdown-drain-fixtures.json':'pkgre-d0-shutdown-drain-fixtures-v1','resource-limit-fixtures.json':'pkgre-d0-resource-limit-fixtures-v1'}
 for name,d in docs.items():
  check(f'{name}-schema',d['schema']==expected_schemas[name],d['schema'])
  check(f'{name}-status',d['status']=='proposed-contract-vectors-not-executed-proof',d['status'])
  check(f'{name}-state-contract-literal',d['stateContract']=='state-contract-v1',d['stateContract'])
  check(f'{name}-redirect-marker-null',d['redirectMarkerSchema'] is None,d['redirectMarkerSchema'])
  ids=[x['id'] for x in d['cases']]
  check(f'{name}-case-ids-unique',len(ids)==len(set(ids)),[len(ids),len(set(ids))])
 check('proposal-schema',proposal['schema']=='pkgre-d0-time-resource-proposal-v1')
 check('proposal-status',proposal['status']=='proposal-not-approved-not-deployment-authority')
 check('proposal-repository-mutation-none',proposal['repositoryMutation'].startswith('none intended'),proposal['repositoryMutation'])
 check('reused-proposal-validation-pass',proposal_validation['result']=='PASS')
 for name,want in proposal_validation['validatedFiles'].items(): check(f'reused-proposal-hash-{name}',sha(PROPOSAL/name)==want,[sha(PROPOSAL/name),want])
 resource=docs['resource-limit-fixtures.json'];timestamp=docs['timestamp-fixtures.json'];shutdown=docs['shutdown-drain-fixtures.json']
 check('resource-observed-rust-archive-bytes-exact',resource['observedBaselines']['rust']['archiveTotalBytes']==129833713,resource['observedBaselines']['rust']['archiveTotalBytes'])
 check('proposal-rust-archive-bytes-exact',proposal['measuredBaseline']['rust']['archiveClosureRehearsal']['rawBytes']==129833713,proposal['measuredBaseline']['rust']['archiveClosureRehearsal']['rawBytes'])
 headroom=proposal['conservativeFormulas']['headroomRule'];rust_limits=proposal['instances']['rust']['limits'];rust_baseline=proposal['measuredBaseline']['rust']
 check('rust-archive-headroom-factor-formula',headroom['archiveTotalRustFactor']==rust_limits['maxArchiveTotalBytes']/rust_baseline['archiveClosureRehearsal']['rawBytes'],headroom['archiveTotalRustFactor'])
 check('rust-inline-headroom-factor-formula',headroom['largestInlineRustFactor']==rust_limits['maxInlineResponseBytes']/rust_baseline['renderer']['largestInlineResponseBytes'],headroom['largestInlineRustFactor'])
 check('report-rust-archive-bytes-exact','129,833,713B' in report)
 check('report-rejects-stale-1.6gb','stale `1.6GB` claim is rejected' in report)
 check('resource-proposal-classification',resource['proposal']['classification']=='proposed-unapproved-resource-and-deployment-policy',resource['proposal']['classification'])
 for eco,x in resource['proposal']['instances'].items(): check(f'{eco}-resource-deployment-not-observed-label',x['classification']=='proposed-unapproved-resource-and-deployment-policy',x['classification'])
 for c in resource['cases']: check(f"case-classification-{c['id']}",c['classification']=='proposed-contract-vector-unexecuted',c['classification'])
 check('report-classification-boundary','## OBSERVED — bounded current facts' in report and '## PROPOSED — exact production envelope for review' in report and 'not production fact' in report)
 check('report-state-contract-literal','state enum=`state-contract-v1`' in report)
 bounded=set(proposal['rejectBehavior']['boundedCodes'])
 check('resource-bounded-codes-match-proposal',set(resource['proposal']['boundedRejectCodes'])==bounded)
 rcases=case_map(resource)
 reject_code={'maxGitFetchNetworkBytes':'FETCH_BYTES','maxGitFetchPackBytes':'FETCH_BYTES','maxGitInflatedObjectBytes':'GIT_OBJECT_LIMIT','maxGitObjects':'GIT_OBJECT_LIMIT','maxGitTreeLogicalBytes':'TREE_LIMIT','maxTreeEntries':'TREE_LIMIT','maxTreeDirectories':'TREE_LIMIT','maxTreeDepth':'TREE_LIMIT','maxPathComponentBytes':'TREE_LIMIT','maxRawPathBytes':'TREE_LIMIT','maxRegularFileBytes':'FILE_LIMIT','maxNonArchiveFileBytes':'FILE_LIMIT','maxMaterializedCheckoutAllocatedBytes':'STATE_SPACE','maxCatalogBytes':'CATALOG_LIMIT','maxRegistries':'CATALOG_LIMIT','maxCategories':'CATALOG_LIMIT','maxPackages':'CATALOG_LIMIT','maxVersions':'CATALOG_LIMIT','maxDependencyEdges':'CATALOG_LIMIT','maxRoutes':'ROUTE_LIMIT','maxInlineResponseBytes':'SNAPSHOT_LIMIT','maxPackumentBytes':'SNAPSHOT_LIMIT','maxSparseRowBytes':'SNAPSHOT_LIMIT','maxArchiveBytes':'ARCHIVE_LIMIT','maxArchiveCount':'ARCHIVE_LIMIT','maxArchiveTotalBytes':'ARCHIVE_LIMIT','maxSnapshotBytes':'SNAPSHOT_LIMIT','maxStateBytes':'STATE_SPACE','maxReloadSeconds':'RELOAD_TIMEOUT'}
 for eco in ('rust','js'):
  source=proposal['instances'][eco];fx=resource['proposal']['instances'][eco];limits=source['limits'];systemd=source['systemd'];calc=source['calculatedAtMaxima']
  check(f'{eco}-fixture-limits-equal-proposal',fx['limits']==limits)
  check(f'{eco}-fixture-systemd-equal-proposal',fx['systemd']==systemd)
  for key,value in limits.items():
   if not key.startswith('max') or key in ('maxConcurrentRequests','maxConcurrentArchiveStreams'): continue
   at=rcases[f'{eco}-{key}-inclusive-boundary'];over=rcases[f'{eco}-{key}-one-over']
   check(f'{eco}-{key}-boundary',at['input'][key]==value and at['expected']['result']=='accept-limit-check')
   check(f'{eco}-{key}-limit-plus-one',over['input'][key]==value+1 and over['expected']['rejectCode']==reject_code[key] and over['expected']['acceptedMutation'] is False)
  single=2097152+2*limits['maxSnapshotBytes']+256*limits['maxRoutes']+128*limits['maxVersions']+96*limits['maxDependencyEdges']+256*limits['maxPackages']+96*limits['maxArchiveCount']
  buffers=limits['maxConcurrentRequests']*proposal['sharedPolicy']['http']['requestBufferBytes']+limits['maxConcurrentArchiveStreams']*limits['streamBufferBytes']
  runtime=134217728 if eco=='rust' else 100663296
  loader=67108864 if eco=='rust' else source['nodeWorker']['workerResidentEnvelopeBytes']
  peak=3*single+runtime+loader+buffers
  check(f'{eco}-single-snapshot-formula',single==calc['singleSnapshotResidentEstimateBytes'],[single,calc['singleSnapshotResidentEstimateBytes']])
  check(f'{eco}-request-stream-buffer-formula',buffers==calc['requestAndStreamBuffersBytes'],[buffers,calc['requestAndStreamBuffersBytes']])
  check(f'{eco}-candidate-peak-formula',peak==calc['processCandidatePeakEstimateBytes'],[peak,calc['processCandidatePeakEstimateBytes']])
  check(f'{eco}-admission-ceiling-formula',calc['admissionCeilingBytes']==systemd['MemoryMaxBytes']-67108864)
  check(f'{eco}-memory-invariants',systemd['MemoryHighBytes']<systemd['MemoryMaxBytes'] and peak<=calc['admissionCeilingBytes'])
  check(f'{eco}-fd-task-invariants',systemd['TasksMax']==64 and systemd['LimitNOFILE']==2048 and 1040<systemd['LimitNOFILE'])
  if eco=='js':
   w=source['nodeWorker'];mib=1048576;heap=(w['resourceLimitsMaxOldGenerationSizeMiB']+w['resourceLimitsMaxYoungGenerationSizeMiB']+w['nearHeapLimitAllowanceMiB'])*mib;resident=heap+w['resourceLimitsStackSizeMiB']*mib+w['workerNonHeapResidentReserveBytes']
   check('js-fixture-node-worker-equal-proposal',fx['nodeWorker']==w)
   check('js-worker-exactly-one',w['workerCount']==1,w['workerCount'])
   check('js-worker-heap-resident-formula',heap==w['workerHeapResidentBudgetBytes'],[heap,w['workerHeapResidentBudgetBytes']])
   check('js-worker-resident-envelope-formula',resident==w['workerResidentEnvelopeBytes'],[resident,w['workerResidentEnvelopeBytes']])
   check('js-worker-code-range-virtual-only',w['resourceLimitsCodeRangeSizeMiB']==32 and w['codeRangeIncludedInResidentEnvelope'] is False)
   check('js-worker-transfer-contract',w['maxTransferableSnapshotBytes']==limits['maxSnapshotBytes'] and w['snapshotArrayBufferOwnership']=='owned' and w['snapshotTransferListRequired'] is True and w['sharedArrayBufferAllowed'] is False and w['structuredCloneAllowed'] is False)
   check('js-worker-systemd-envelope',systemd['MemoryHighBytes']==805306368 and systemd['MemoryMaxBytes']==1073741824 and resident<systemd['MemoryMaxBytes'])
   at=rcases['js-memory-estimate-at-admission-ceiling']['input'];over=rcases['js-memory-estimate-one-over-admission-ceiling']['input']
   check('js-memory-admission-boundary-vector',at=={'estimatedCandidatePeakBytes':calc['admissionCeilingBytes'],'MemoryMaxBytes':systemd['MemoryMaxBytes'],'reserveBytes':67108864},at)
   check('js-memory-admission-one-over-vector',over=={'estimatedCandidatePeakBytes':calc['admissionCeilingBytes']+1,'MemoryMaxBytes':systemd['MemoryMaxBytes'],'reserveBytes':67108864},over)
  check(f'{eco}-quota-equals-state-limit',source['zfs']['quotaBytes']==limits['maxStateBytes'])
  quota=source['zfs']['quotaBytes'];floor=85*quota//100;twice=2*limits['maxMaterializedCheckoutAllocatedBytes'];used=floor-twice
  check(f'{eco}-quota-floor',rcases[f'{eco}-state-preflight-at-inclusive-boundary']['input']['quota85PercentFloorBytes']==floor,floor)
  check(f'{eco}-quota-boundary-formula',used+twice==floor,[used,twice,floor])
  check(f'{eco}-quota-over-reject',rcases[f'{eco}-state-preflight-one-byte-over']['expected']['sumBytes']==floor+1)
  check(f'{eco}-quota-free-short-reject',rcases[f'{eco}-state-preflight-free-space-one-byte-short']['input']['filesystemFreeBytes']==floor-1)
  measured=proposal['measuredBaseline'][eco];archive=measured['archiveClosureRehearsal'] if eco=='rust' else measured['archiveClosure'];ratios=source['growthHeadroomRatios']
  actual_ratios={'archiveCount':limits['maxArchiveCount']/archive['archives'],'archiveTotalBytes':limits['maxArchiveTotalBytes']/archive['rawBytes'],'largestArchive':limits['maxArchiveBytes']/archive['largestBytes'],'gitTreeLogical':limits['maxGitTreeLogicalBytes']/measured['gitTreeLogicalBytes'],'largestInlineResponse':limits['maxInlineResponseBytes']/measured['renderer']['largestInlineResponseBytes'],'packages':limits['maxPackages']/measured['packages'],'routes':limits['maxRoutes']/measured['routeInventory']['allObservedPublicUrls'],'treeEntries':limits['maxTreeEntries']/measured['gitTreeEntries'],'versions':limits['maxVersions']/measured['versions']}
  if eco=='rust': actual_ratios.update(dependencyEdges=limits['maxDependencyEdges']/measured['dependencyEdges'],largestSparseRow=limits['maxSparseRowBytes']/measured['renderer']['largestSparseRowBytes'],rehearsedRepoPlusCheckoutPeakToQuota=limits['maxStateBytes']/archive['repoPlusCheckoutPeakAllocatedBytes'])
  else: actual_ratios.update(currentCheckoutToQuota=limits['maxStateBytes']/measured['checkoutFilesystemApparentBytes'])
  check(f'{eco}-headroom-ratio-keys',set(actual_ratios)==set(ratios),[sorted(actual_ratios),sorted(ratios)])
  for key,actual in actual_ratios.items():
   decimals=len(str(ratios[key]).split('.')[1]) if '.' in str(ratios[key]) else 0
   check(f'{eco}-headroom-ratio-{key}',round(actual,decimals)==ratios[key],[actual,ratios[key]])
 check('rust-state-budget-formula',536870912+5*536870912+134217728+939524096==4294967296)
 check('js-state-budget-formula',268435456+5*268435456+67108864+469762048==2147483648)
 http=proposal['sharedPolicy']['http']
 http_vectors={'http-raw-target-at-inclusive-boundary':('rawTargetBytes',http['maxRawTargetBytes']),'http-raw-target-one-over':('rawTargetBytes',http['maxRawTargetBytes']+1),'http-header-count-at-inclusive-boundary':('headerCount',http['maxHeaderCount']),'http-header-count-one-over':('headerCount',http['maxHeaderCount']+1),'http-total-headers-at-inclusive-boundary':('totalHeaderBytes',http['maxTotalHeaderBytes']),'http-total-headers-one-over':('totalHeaderBytes',http['maxTotalHeaderBytes']+1),'http-single-header-at-inclusive-boundary':('singleHeaderFieldBytes',http['maxSingleHeaderFieldBytes']),'http-single-header-one-over':('singleHeaderFieldBytes',http['maxSingleHeaderFieldBytes']+1)}
 for cid,(key,value) in http_vectors.items(): check(f'{cid}-value',rcases[cid]['input'][key]==value,[rcases[cid]['input'][key],value])
 check('http-body-vectors',rcases['http-empty-unframed-body']['expected']['result']=='accept-request' and rcases['http-nonzero-body']['expected']['httpStatus']==413 and rcases['http-framed-zero-body']['expected']['httpStatus']==413)
 for cid in ('http-request-concurrency-next-rejected','http-archive-concurrency-next-rejected'):
  e=rcases[cid]['expected'];check(f'{cid}-fixed-503',e['httpStatus']==503 and e['Retry-After']=='1' and e['bodyBytes']==0)
 life=proposal['sharedPolicy']['lifecycle'];sp=shutdown['proposal']
 for key in ('httpDrainDeadlineSeconds','systemdTimeoutStopSeconds','requestHeaderReadTimeoutSeconds','requestIdleTimeoutSeconds','requestTotalLeaseSeconds','archiveStreamLeaseSeconds','oldGenerationLeaseSeconds','shutdownLeaseOverrideSeconds'): check(f'lifecycle-{key}',sp[key]==life[key],[sp[key],life[key]])
 check('lifecycle-sigkill-margin',sp['sigkillMarginSeconds']==life['sigkillAfterApplicationDeadlineSeconds']==5)
 clock=proposal['sharedPolicy']['clock'];tp=timestamp['proposal']
 check('timestamp-future-skew',tp['maxFutureSkewSeconds']==clock['maxFutureSkewSeconds']==300)
 check('timestamp-trusted-sync',tp['trustedSyncStableSeconds']==clock['timeSyncPrerequisite']['stableBeforeAcceptanceSeconds']==600)
 check('timestamp-dual-clock',tp['maxBackwardRealtimeMovementSeconds']==clock['maxBackwardRealtimeMovementSeconds']==5 and tp['maxRealtimeVsMonotonicDeviationSeconds']==clock['maxRealtimeVsMonotonicDeviationSeconds']==2)
 for name,d in docs.items():
  for c in d['cases']:
   e=c['expected']
   if e.get('result')=='reject' and 'acceptedMutation' in e: check(f'{name}-{c["id"]}-reject-no-accepted-mutation',e['acceptedMutation'] is False)
 report_refs=('timestamp-fixtures.json','shutdown-drain-fixtures.json','resource-limit-fixtures.json','validate.py','validation.json','SHA256SUMS')
 for ref in report_refs: check(f'report-reference-{ref}',ref in report)
 patterns={'private-key':re.compile(r'BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY'),'aws-access-key':re.compile(r'AKIA[0-9A-Z]{16}'),'github-token':re.compile(r'gh[pousr]_[A-Za-z0-9]{20,}'),'slack-token':re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}'),'generic-secret-assignment':re.compile(r'(?i)(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*["\'][^"\'\n]{12,}["\']')}
 scanned=[REPORT,ROOT/'validate.py',*(ROOT/name for name in FIXTURES),PROPOSAL/'README.md',PROPOSAL/'proposal.json',PROPOSAL/'validate.py',PROPOSAL/'validation.json']
 hits=[]
 for path in scanned:
  text=path.read_text(errors='replace')
  for label,pattern in patterns.items():
   for m in pattern.finditer(text): hits.append({'file':str(path.relative_to(WORK)),'pattern':label,'matchSha256':hashlib.sha256(m.group(0).encode()).hexdigest()})
 check('secret-scan-no-pattern-matches',not hits,hits)
 files=[REPORT,ROOT/'validate.py',*(ROOT/name for name in FIXTURES),PROPOSAL/'README.md',PROPOSAL/'proposal.json',PROPOSAL/'validate.py',PROPOSAL/'validation.json']
 result={'schema':'pkgre-d0-resource-time-lifecycle-validation-v1','result':'PASS','checkCount':len(checks),'checks':checks,'validatedFiles':{str(path.relative_to(WORK)):sha(path) for path in files},'secretScan':{'result':'PASS','patterns':sorted(patterns),'filesScanned':len(scanned),'matches':0},'repositoryMutation':'none;validation is artifact-only and does not invoke source builds/probes'}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 print(f'PASS {len(checks)} checks;secret-scan PASS;archiveBytes=129833713;stateContract=state-contract-v1')
except Exception as e:
 print(f'FAIL {e}',file=sys.stderr);sys.exit(1)
