#!/usr/bin/env python3
import hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
P=ROOT/'proposal.json';M=ROOT/'README.md';V=ROOT/'validation.json';N=ROOT/'node-worker-contract-probe.cjs'
d=json.loads(P.read_text());md=M.read_text();checks=[]
def ck(name,ok,detail=None):
 checks.append({'name':name,'pass':bool(ok),'detail':detail});
 if not ok: raise AssertionError(f'{name}: {detail}')
def run_node_probe(mode,node_options):
 env=os.environ.copy()
 if node_options is None: env.pop('NODE_OPTIONS',None)
 else: env['NODE_OPTIONS']=node_options
 completed=subprocess.run(['node',str(N),mode],check=True,capture_output=True,text=True,env=env)
 return json.loads(completed.stdout)
ck('schema',d['schema']=='pkgre-d0-time-resource-proposal-v1')
ck('status',d['status']=='proposal-not-approved-not-deployment-authority')
ck('classification-separation',all(k in d for k in ['measuredBaseline','conservativeFormulas','sharedPolicy','hardBlockers']))
for eco in ('rust','js'):
 x=d['instances'][eco];l=x['limits'];c=x['calculatedAtMaxima'];s=x['systemd'];m=d['measuredBaseline'][eco]
 single=2097152+2*l['maxSnapshotBytes']+256*l['maxRoutes']+128*l['maxVersions']+96*l['maxDependencyEdges']+256*l['maxPackages']+96*l['maxArchiveCount']
 req=l['maxConcurrentRequests']*d['sharedPolicy']['http']['requestBufferBytes']+l['maxConcurrentArchiveStreams']*l['streamBufferBytes']
 runtime=134217728 if eco=='rust' else 100663296
 loader=67108864 if eco=='rust' else x['nodeWorker']['workerResidentEnvelopeBytes']
 peak=3*single+runtime+loader+req
 ck(f'{eco}-single-snapshot-formula',single==c['singleSnapshotResidentEstimateBytes'],[single,c['singleSnapshotResidentEstimateBytes']])
 ck(f'{eco}-request-buffer-formula',req==c['requestAndStreamBuffersBytes'],[req,c['requestAndStreamBuffersBytes']])
 ck(f'{eco}-candidate-peak-formula',peak==c['processCandidatePeakEstimateBytes'],[peak,c['processCandidatePeakEstimateBytes']])
 ck(f'{eco}-memory-order',s['MemoryHighBytes']<s['MemoryMaxBytes'] and peak<=s['MemoryMaxBytes']-67108864)
 ck(f'{eco}-task-fd',s['TasksMax']==64 and s['LimitNOFILE']==2048 and 1040<s['LimitNOFILE'])
 ck(f'{eco}-state-quota',l['maxStateBytes']==x['zfs']['quotaBytes'])
 ck(f'{eco}-tree-headroom',l['maxGitTreeLogicalBytes']>m['gitTreeLogicalBytes'] and l['maxTreeEntries']>m['gitTreeEntries'])
 ck(f'{eco}-graph-headroom',l['maxPackages']>=m['packages'] and l['maxVersions']>=m['versions'] and l['maxDependencyEdges']>=m['dependencyEdges'])
 ck(f'{eco}-response-headroom',l['maxInlineResponseBytes']>=m['renderer']['largestInlineResponseBytes'])
 ar=m['archiveClosureRehearsal'] if eco=='rust' else m['archiveClosure']
 ck(f'{eco}-archive-headroom',l['maxArchiveBytes']>=ar['largestBytes'] and l['maxArchiveCount']>=ar['archives'] and l['maxArchiveTotalBytes']>=ar['rawBytes'])
 ck(f'{eco}-limits-positive',all(isinstance(v,int) and v>=0 for k,v in l.items() if k.startswith('max')))
 if eco=='js':
  w=x['nodeWorker'];mib=1048576;r=w['resourceLimits'];h=w['startupHandshake']
  heap=h['requiredInitialHeapSizeLimitBytes']+w['nearHeapLimitAllowanceBytes']
  resident=heap+r['stackSizeMb']*mib+w['codeRangeResidentBudgetBytes']+w['workerNonHeapResidentReserveBytes']
  ck('js-worker-exactly-one-path',w['workerCount']==1 and w['alternateWorkerConstructorAllowed'] is False,[w['workerCount'],w['alternateWorkerConstructorAllowed']])
  ck('js-worker-runtime-contract',w['nodeVersion']=='24.19.0' and w['parentExecArgv']==[] and w['workerExecArgv']==[] and w['nodeOptionsEnvironment']=='absent-before-node-exec' and w['operatorOrCatalogSuppliedNodeOptionsAllowed'] is False)
  ck('js-worker-forbidden-parent-options',w['nodeOptionNameNormalization']=='token-before-equals;underscore-to-dash;exact-name-match' and w['forbiddenParentV8OptionsNormalized']==['--max-heap-size','--max-old-space-size','--max-old-space-size-percentage','--max-semi-space-size'])
  ck('js-worker-resource-limits-exact',r=={'maxOldGenerationSizeMb':192,'maxYoungGenerationSizeMb':32,'codeRangeSizeMb':32,'stackSizeMb':4},r)
  ck('js-worker-startup-handshake',h=={'beforeCatalogBytesProcessed':True,'failureAction':'terminate-worker-and-reject-candidate','requestedResourceLimitsReadbackRequired':True,'requiredInitialHeapSizeLimitBytes':251658240,'workerHeapStatisticsReadbackRequired':True},h)
  ck('js-worker-heap-maximum-formula',heap==w['workerHeapMaximumBytes'],[heap,w['workerHeapMaximumBytes']])
  ck('js-worker-resident-envelope-formula',resident==w['workerResidentEnvelopeBytes'],[resident,w['workerResidentEnvelopeBytes']])
  ck('js-worker-code-range-resident-budget',w['codeRangeResidentBudgetBytes']==r['codeRangeSizeMb']*mib)
  ck('js-worker-transfer-contract',w['maxTransferableSnapshotBytes']==l['maxSnapshotBytes'] and w['snapshotArrayBufferOwnership']=='exclusive' and w['snapshotArrayBufferTransferRequired'] is True and w['snapshotArrayBufferCloneAllowed'] is False and w['sharedArrayBufferAllowed'] is False)
  ck('js-worker-systemd-envelope',s['MemoryHighBytes']==805306368 and s['MemoryMaxBytes']==1073741824 and w['workerResidentEnvelopeBytes']<s['MemoryMaxBytes'])
ck('rust-state-formula',536870912+5*536870912+134217728+939524096==4294967296)
ck('js-state-formula',268435456+5*268435456+67108864+469762048==2147483648)
clock=d['sharedPolicy']['clock'];life=d['sharedPolicy']['lifecycle'];http=d['sharedPolicy']['http'];watch=d['sharedPolicy']['watcher'];reload=d['sharedPolicy']['reload']
ck('clock-exact',clock['maxFutureSkewSeconds']==300 and clock['maxRealtimeVsMonotonicDeviationSeconds']==2 and clock['maxBackwardRealtimeMovementSeconds']==5)
ck('watch-exact',watch['pollIntervalSeconds']==60 and watch['pollJitterSeconds']==15 and watch['fetchOverallTimeoutSeconds']==30 and watch['retryBackoffMaxSeconds']==900)
ck('reload-exact',reload['materializeTimeoutSeconds']==45 and reload['postFetchEndToEndTimeoutSeconds']==120)
ck('lifecycle-exact',life['httpDrainDeadlineSeconds']==30 and life['archiveStreamLeaseSeconds']==120 and life['oldGenerationLeaseSeconds']==120 and life['systemdTimeoutStopSeconds']==35)
ck('http-exact',http['maxRawTargetBytes']==4096 and http['maxHeaderCount']==64 and http['maxTotalHeaderBytes']==32768 and http['maxRequestBodyBytes']==0 and http['maxConcurrentRequests']==256 and http['maxConcurrentArchiveStreams']==64)
for token in ['300s','60s±15s','30s/35s/5s','4,096B/64/32,768B/8,192B','384MiB/512MiB','768MiB/1GiB','440,401,920B','912,261,120B','1,006,632,960B','4GiB','2GiB','24h','72h','7d','14d','30d']:
 ck('markdown-token-'+token,token in md)
resource_limits={'maxYoungGenerationSizeMb':32,'maxOldGenerationSizeMb':192,'codeRangeSizeMb':32,'stackSizeMb':4}
baseline=run_node_probe('baseline',None)
override=run_node_probe('override','--max-old-space-size=64')
expected_baseline={'mode':'baseline','nodeVersion':'v24.19.0','nodeOptionsPresent':False,'parentExecArgv':[],'parentResourceLimitsReadback':resource_limits,'workerExecArgv':[],'workerResourceLimitsReadback':resource_limits,'workerHeapSizeLimitBytes':251658240,'transfer':{'expectedSha256':'630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd','receiverByteLength':32,'receiverSha256':'630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd','senderArrayBufferByteLength':0,'senderByteViewByteLength':0,'senderWordViewByteLength':0}}
expected_override={'mode':'override','nodeVersion':'v24.19.0','nodeOptionsPresent':True,'parentExecArgv':[],'parentResourceLimitsReadback':resource_limits,'workerExecArgv':[],'workerResourceLimitsReadback':resource_limits,'workerHeapSizeLimitBytes':117440512}
ck('node-worker-baseline-probe-exact',baseline==expected_baseline,baseline)
ck('node-worker-parent-override-probe-exact',override==expected_override,override)
ck('node-worker-readback-alone-insufficient',override['parentResourceLimitsReadback']==baseline['parentResourceLimitsReadback'] and override['workerResourceLimitsReadback']==baseline['workerResourceLimitsReadback'] and override['workerHeapSizeLimitBytes']!=baseline['workerHeapSizeLimitBytes'])
repos={}
for name in ('pkgre','pkgre-rust','pkgre-js'):
 r=Path('/home/dev0/repos')/name
 raw=subprocess.run(['git','-C',str(r),'status','--porcelain=v1'],check=True,capture_output=True).stdout
 repos[name]={'porcelainSha256':hashlib.sha256(raw).hexdigest(),'clean':raw==b''}
 ck('source-clean-'+name,raw==b'',repos[name])
ck('output-containment',all(p.resolve().parent==ROOT for p in [P,M,V,N,ROOT/'validate.py']))
result={'schema':'pkgre-d0-time-resource-validation-v1','result':'PASS','checks':checks,'sourceRepositoryStatus':repos,'validatedFiles':{'proposal.json':hashlib.sha256(P.read_bytes()).hexdigest(),'README.md':hashlib.sha256(M.read_bytes()).hexdigest(),'validate.py':hashlib.sha256((ROOT/'validate.py').read_bytes()).hexdigest(),'node-worker-contract-probe.cjs':hashlib.sha256(N.read_bytes()).hexdigest()}}
V.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(f"PASS {len(checks)} checks")
