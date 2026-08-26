#!/usr/bin/env python3
import collections, hashlib, json, os, pathlib, shutil, subprocess, tomllib
OUT=pathlib.Path(__file__).resolve().parent
WS=OUT.parent
CAT=pathlib.Path('/home/dev0/repos/pkgre-rust')
IMPL_CAPTURE=WS/'d0-pkgre-066293df'
RENDER=IMPL_CAPTURE/'performance/rust-site'
ROUTES=WS/'d0-route-inventory/routes.json'
GITINV=WS/'d0-git-storage-inventory/repositories.json'
REHEARSAL=pathlib.Path('/home/dev0/repos/pkgre/fixtures/d0-v1/archive-git-rehearsal')
CLOSURE=IMPL_CAPTURE/'logs/cargo-closure-summary.json'
CAT_COMMIT='f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b'
IMPL_COMMIT='066293df21743cbf41fb571a38f2bb94059e7274'
EMPTY_SHA='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()
def dump(path,obj):
    path.write_text(json.dumps(obj,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
def dump_jsonl(path,rows):
    with open(path,'w',encoding='utf-8',newline='\n') as f:
        for row in rows: f.write(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n')
def load_toml(path): return tomllib.loads(path.read_text())
def git(repo,*args): return subprocess.run(['git','-C',str(repo),*args],text=True,capture_output=True,check=True).stdout.strip()

assert git(CAT,'rev-parse','HEAD')==CAT_COMMIT
assert git(CAT,'status','--porcelain=v2')==''
assert git('/home/dev0/repos/pkgre','cat-file','-t',IMPL_COMMIT)=='commit'

registry_dir=CAT/'registry'
main=load_toml(registry_dir/'main.toml')
lock=load_toml(registry_dir/'main.lock')
downloads=json.loads((registry_dir/'downloads.json').read_text())
assert main['schema']==lock['schema']==4 and downloads['schema']==1
assert main['registry']['name']==lock['registry']['name']=='main'

# Exact category declarations and permanent homes.
categories=[]; homes=[]
for cname,stub in sorted(main['categories'].items()):
    record=dict(stub)
    source='registry/main.toml'
    if 'file' in stub:
        source='registry/'+stub['file']
        ext=load_toml(registry_dir/stub['file'])
        assert ext['schema']==4
        record={**ext}
    may=record.get('may-depend-on',[])
    mirror=record.get('mirror',{})
    publish=record.get('publish',{})
    for name,versions in sorted(mirror.items()):
        homes.append({'audience':'public-provisional','category':cname,'declaration':'mirror','name':name,'registry':'main','sourceFile':source,'versions':versions})
    for name,spec in sorted(publish.items()):
        homes.append({'audience':'public-provisional','category':cname,'declaration':'publish','name':name,'registry':'main','sourceFile':source,**spec})
    categories.append({'category':cname,'homeCount':len(mirror)+len(publish),'mayDependOn':may,'mirrorHomeCount':len(mirror),'mirrorVersionCount':sum(len(v) for v in mirror.values()),'publishHomeCount':len(publish),'publishTagCount':sum(len(v.get('tags',[])) for v in publish.values()),'registry':'main','sourceFile':source})
homes.sort(key=lambda x:(x['registry'],x['category'],x['name']))
assert len(homes)==911 and len(categories)==9
name_categories={x['name']:x['category'] for x in lock['names']}
assert len(name_categories)==911 and set(name_categories)=={x['name'] for x in homes}
for h in homes: assert name_categories[h['name']]==h['category']

# Authoritative archive rehearsal and point-in-time route inventory.
result=json.loads((REHEARSAL/'download-results.json').read_text())
summary=json.loads((REHEARSAL/'download-summary.json').read_text())
metrics=json.loads((REHEARSAL/'git-metrics.json').read_text())
assert result['summary']['raw_unique_bytes']==summary['raw_unique_bytes']==metrics['raw_unique_bytes']==metrics['checkout_verified_bytes']==129833713
assert summary['route_count']==summary['unique_hash_count']==summary['verified_unique_count']==747
archive_by_sha={x['sha256']:x for x in result['objects']}
assert len(archive_by_sha)==747
route_doc=json.loads(ROUTES.read_text())
route_by_key={(x['host'],x['rawPath']):x for x in route_doc['routes']}
assert len(route_by_key)==2072

download_by_key={(x['registry'],x['name'],x['version']):x for x in downloads['routes']}
assert len(download_by_key)==747
package_by_key={(x['name'],x['version']):x for x in lock['packages']}
assert len(package_by_key)==747
basis_crates={p.stem:p for p in (registry_dir/'objects/crates').glob('*.crate')}
assert len(basis_crates)==3
version_rows=[]; dep_edges=0; pubtimes=[]; source_row_bytes=0; max_source=(0,None)
for p in sorted(lock['packages'],key=lambda x:(x['name'],x['version'])):
    key=('main',p['name'],p['version']); dr=download_by_key[key]
    assert dr['sha256']==p['crate-sha256']
    srpath=registry_dir/'objects/rows'/f"{p['source-row-sha256']}.json"
    sr=json.loads(srpath.read_text()); srb=srpath.stat().st_size
    assert sha(srpath)==p['source-row-sha256']
    dep_edges+=len(sr.get('deps',[])); source_row_bytes+=srb
    if srb>max_source[0]: max_source=(srb,srpath.name)
    if sr.get('pubtime'): pubtimes.append(sr['pubtime'])
    ar=archive_by_sha[p['crate-sha256']]
    raw=f"/v1/main/{p['name']}/{p['version']}/{p['crate-sha256']}"
    legacy=route_by_key[('dl.rust.pkg.re',raw)]; canonical=route_by_key[('rust.pkg.re',raw)]
    assert legacy['observed']['status']==307 and canonical['observed']['status']==404
    destination=legacy['observed']['semanticHeaders']['location'][0]
    if p['source']['kind']=='crates-io': assert destination==ar['url']
    else: assert destination==f"https://rust.pkg.re/crates/{p['crate-sha256']}.crate" and ar['url'].startswith('git:')
    body=basis_crates.get(p['crate-sha256'])
    if body: assert body.stat().st_size==ar['bytes'] and sha(body)==p['crate-sha256']
    row={'archiveRehearsal':{'bytes':ar['bytes'],'contentLength':ar.get('content_length'),'etag':ar.get('etag'),'lastModified':ar.get('last_modified'),'retrievalUrl':ar['url'],'status':ar.get('status'),'transport':ar['transport'],'verified':ar['ok']},'audience':'public-provisional','category':name_categories[p['name']],'compatibility':{'canonicalObserved':{'bodyLength':canonical['observed']['bodyLength'],'bodySha256':canonical['observed']['bodySha256'],'status':canonical['observed']['status']},'destination':destination,'legacyObserved':{'bodyLength':legacy['observed']['bodyLength'],'bodySha256':legacy['observed']['bodySha256'],'semanticHeaders':legacy['observed']['semanticHeaders'],'status':legacy['observed']['status']},'path':raw},'currentCatalogBody':{'bytes':body.stat().st_size if body else None,'path':f"registry/objects/crates/{p['crate-sha256']}.crate",'present':bool(body)},'indexRowSha256':p['index-row-sha256'],'name':p['name'],'registry':'main','sha256':p['crate-sha256'],'source':p['source'],'sourceRecord':sr,'sourceRowBytes':srb,'sourceRowPath':f"registry/objects/rows/{p['source-row-sha256']}.json",'sourceRowSha256':p['source-row-sha256'],'state':p['state'],'version':p['version']}
    version_rows.append(row)
assert dep_edges==5518 and source_row_bytes==1199549 and max_source==(53873,'3c50bc80756af60a2a280fb6a7335ff8eeaf61ed36d522b4f6db3e8032995115.json')
assert len(pubtimes)==744 and min(pubtimes)=='2016-05-15T12:20:41Z' and max(pubtimes)=='2026-08-09T23:14:46Z'

# Admissions: preserve complete candidate evidence per admitted identity.
admission_rows=[]
for manifest_path in sorted((registry_dir/'admissions').glob('*.toml')):
    stem=manifest_path.stem; lock_path=manifest_path.with_suffix('.lock')
    manifest=load_toml(manifest_path); alock=load_toml(lock_path)
    candidates={(x['name'],x['candidate']['version']):x for x in alock['plan']['candidates']}
    for x in manifest['admit']:
        admission_rows.append({'admissionLock':{'admittedAt':alock['admitted-at'],'bytes':lock_path.stat().st_size,'manifestSha256':alock['manifest-sha256'],'path':f'registry/admissions/{lock_path.name}','plan':{k:v for k,v in alock['plan'].items() if k!='candidates'},'sha256':sha(lock_path)},'candidateEvidence':candidates[(x['name'],x['version'])],'identity':x,'manifest':{'bytes':manifest_path.stat().st_size,'path':f'registry/admissions/{manifest_path.name}','schema':manifest['schema'],'sha256':sha(manifest_path)}})
assert len(admission_rows)==3

# Fixed renderer inventory and corresponding observed public representations.
render_rows=[]; render_bytes=0; sparse_count=0; sparse_records=0; max_sparse=(0,None)
for path in sorted((p for p in RENDER.rglob('*') if p.is_file()),key=lambda p:p.relative_to(RENDER).as_posix().encode()):
    rel=path.relative_to(RENDER).as_posix(); raw='/'+rel; b=path.stat().st_size; digest=sha(path); render_bytes+=b
    if rel in ('.nojekyll','CNAME'): kind='provider-adapter'
    elif rel in ('config.json','downloads.json','release.json'): kind='json'
    elif rel.startswith('crates/'): kind='archive'
    else:
        kind='sparse-row'; sparse_count+=1; sparse_records+=sum(1 for line in path.read_bytes().splitlines() if line)
        if b>max_sparse[0]: max_sparse=(b,rel)
    obs=route_by_key[('rust.pkg.re',raw)]
    assert obs['observed']['status']==200 and obs['observed']['bodyLength']==b and obs['observed']['bodySha256']==digest
    planned_ct={'json':'application/json; charset=utf-8','sparse-row':'text/plain; charset=utf-8','archive':'application/octet-stream','provider-adapter':None}[kind]
    render_rows.append({'audience':'public' if kind!='provider-adapter' else 'control-only/provider-adapter','bytes':b,'currentObserved':{'contentType':(obs['observed']['headers'].get('content-type') or [None])[0],'semanticHeaders':obs['observed']['semanticHeaders'],'status':200},'d8ToD14Behavior':obs['d8ToD14Behavior'],'intentionalChanges':obs['intentionalChanges'],'kind':kind,'path':raw,'plannedDynamicContentType':planned_ct,'sha256':digest,'source':'fixed render from pkgre@'+IMPL_COMMIT+' + pkgre-rust@'+CAT_COMMIT})
assert len(render_rows)==563 and render_bytes==2129784 and sparse_count==555 and sparse_records==747 and max_sparse==(107745,'we/b-/web-sys')
render_inventory_bytes=''.join(json.dumps({'path':x['path'][1:],'length':x['bytes'],'sha256':x['sha256']},sort_keys=True,separators=(',',':'))+'\n' for x in render_rows).encode()

# Git/storage facts from the separately validated read-only D0 inventory.
gitdoc=json.loads(GITINV.read_text())
rustgit=next(x for x in gitdoc['repositories'] if x.get('name')=='pkgre-rust' or x.get('path')=='/home/dev0/repos/pkgre-rust')
# Keep only summary facts here; full evidence remains in the referenced inventory.
git_summary={'basisInventoryObservedAt':gitdoc['observed_at'],'canonicalTreeSha256':'ebb632e21d7553d46da4b3db0c4dac5be1cdd6ec2b51a1c21a3c59e511492355','complete':True,'developmentCheckout':True,'fsckFullStrict':'pass','gitObjectFormat':'sha1','hashHexLength':40,'localOrigin':'git@github.com:pkgre/rust.git','nonShallow':True,'productionLayoutProved':False,'treeEntries':773,'uniqueBlobBytes':1958607,'uniqueBlobCount':763,'unexpectedTreeGitlinks':0,'unexpectedTreeSymlinks':0}

closure=json.loads(CLOSURE.read_text())
assert closure['lock_package_count']==174
assert closure['roots']['pkgre-rust']['package_count_including_root']==55
assert closure['roots']['pkgre-proxy']['package_count_including_root']==155
shutil.copyfile(CLOSURE,OUT/'cargo-closure.json')

file_hashes={str(p.relative_to(CAT)): {'bytes':p.stat().st_size,'sha256':sha(p)} for p in [registry_dir/'main.toml',registry_dir/'main.lock',registry_dir/'downloads.json']}
blockers=[
 {'id':'D0-SCOPE','fact':'This Rust catalog/render inventory is not the complete cross-domain D0 gate;deployment/network/TLS/governance/signing/raw-target rows remain separate.'},
 {'id':'FRESH-REFETCH','fact':'No fetch was run in this reconstruction; D0 requires immediate fetch/prune/upstream verification before first edit.'},
 {'id':'AUDIENCE-SCHEMA','fact':'Schema 4 has no audience field; public classifications here are provisional migration classifications.'},
 {'id':'BODY-IN-SOURCE','fact':'Catalog basis contains 3/747 archive bodies; 744 verified bodies remain to be imported by an authorized future migration.'},
 {'id':'ARCHIVE-CAPACITY','fact':'Rehearsal proves current closure on one tmpfs host only; append-only history growth, provider ceiling, production quota, and backup/restore remain unproved.'},
 {'id':'SIGNATURE-AUTHORITY','fact':'Exact protected writer/check/environment rows and v1 SSH-Ed25519 allowedSigners production authority remain separate blockers.'},
 {'id':'HEADER-FREEZE','fact':'Current sparse Content-Type is application/octet-stream while plan requires text/plain; deterministic validators/owned headers require D1 fixtures.'},
 {'id':'DOWNLOAD-RAW-EDGE','fact':'Known 747 legacy redirects were observed, but malformed/raw-target/alias/nginx H1/H2 behavior is a separate D0 proof.'},
 {'id':'CARGO-OFFLINE-PRE-D5','fact':'Current .cargo/config.toml has offlineExplicit=false;the operator-approved plan amendment makes [net] offline=true plus its self-host/cold-replay proof a mandatory pre-D5 gate,not a D0 mutation or blocker.'},
 {'id':'REQWEST-DELTA','fact':'Exact current proxy/indexer feature closures are frozen; proposed post-reqwest lock/feature delta does not exist until an authorized change.'},
 {'id':'DYNAMIC-SERVER','fact':'No pkgre-rust-serve package/Nix attribute or live two-snapshot resource measurement exists at the fixed implementation basis.'}
]

inventory={
 'schema':'pkgre-d0-rust-inventory-v1',
 'classification':{'observed':'Values under observedFacts and generated JSONL are measurements of fixed artifacts or cited point-in-time evidence.','planRequirements':'Normative target values copied from the canonical plan,not observations.','proposals':'No proposal value is promoted to observed fact in this inventory.'},
 'basis':{'catalog':{'commit':CAT_COMMIT,'fullRef':'refs/heads/main','localCurrentAndClean':True,'repository':'pkgre-rust'},'implementationRender':{'commit':IMPL_COMMIT,'repository':'pkgre','reviewedUpstreamBasis':True,'sourceCaptureSha256':'33526e0f3276a5dd79f2f7d8d54580547957bcb21a3a8941c7ba7b6153d30b26'},'rendererEquivalence':{'deployedWorkflowPin':'ae1dfbfd4e965dffb538e356f005e4fbb32fdb77','fileCount':563,'inventorySha256':'74fca0feee12753226ba8c5cebeb272cf8863b157879dcccfdc0a52650018f8e','result':'byte-identical-to-reviewed-renderer'},'archiveRehearsalAuthority':{'committedAtPkgreTip':'1d44dfeaeafef2b1a5341c13bf73647dcbc925ec','tree':'fixtures/d0-v1/archive-git-rehearsal','catalogCommit':CAT_COMMIT,'downloadSummarySha256':sha(REHEARSAL/'download-summary.json'),'downloadResultsSha256':sha(REHEARSAL/'download-results.json'),'gitMetricsSha256':sha(REHEARSAL/'git-metrics.json'),'sha256sumsVerified':True}},
 'observedFacts':{
  'catalog':{'schema':4,'registry':main['registry'],'registryCount':1,'categories':categories,'categoryCount':9,'permanentHomeCount':911,'lockedVersionCount':747,'namesWithVersions':len({x['name'] for x in lock['packages']}),'reservedHomesWithoutVersions':911-len({x['name'] for x in lock['packages']}),'activeVersionCount':sum(x['state']=='active' for x in lock['packages']),'dependencyEdgeCount':dep_edges,'sourceKinds':dict(collections.Counter(x['source']['kind'] for x in lock['packages'])),'sourceUrls':['https://github.com/pkgre/pkgre'],'pubtime':{'count':len(pubtimes),'earliest':min(pubtimes),'latest':max(pubtimes)},'fileHashes':file_hashes,'sourceRowObjects':{'bytes':source_row_bytes,'count':747,'largestBytes':max_source[0],'largestPath':'registry/objects/rows/'+max_source[1]},'admissionBatchCount':1,'admittedIdentityCount':3},
  'currentCatalogArchives':{'bytes':sum(p.stat().st_size for p in basis_crates.values()),'count':len(basis_crates),'declaredRoutes':747,'missingBodies':744},
  'archiveRehearsal':{'archiveCount':747,'rawUniqueBytes':129833713,'logicalRouteBytes':129833713,'largestArchiveBytes':summary['largest_archive_bytes'],'largestArchiveSha256':summary['largest_archive_sha256'],'downloadSeconds':summary['download_seconds'],'failedCount':0,'git':{'objectFormat':metrics['object_format'],'looseRepoApparentBytes':metrics['loose_repo_apparent_bytes'],'packedRepoApparentBytes':metrics['packed_repo_apparent_bytes'],'packedRepoAllocatedBytes':metrics['packed_repo_allocated_bytes'],'bareRepoApparentBytes':metrics['bare_repo_apparent_bytes'],'bareRepoAllocatedBytes':metrics['bare_repo_allocated_bytes'],'repoPlusCheckoutPeakApparentBytes':metrics['checkout_repo_apparent_bytes']+metrics['checkout_tree_apparent_bytes'],'repoPlusCheckoutPeakAllocatedBytes':metrics['checkout_repo_allocated_bytes']+metrics['checkout_tree_allocated_bytes'],'importSeconds':metrics['import_seconds'],'packSeconds':metrics['pack_seconds'],'bareCloneSeconds':metrics['bare_clone_seconds'],'fixedRefFetchSeconds':metrics['fetch_seconds'],'checkoutCloneSeconds':metrics['checkout_clone_seconds'],'strictFsck':'pass','checkoutRehash':'pass'},'scope':'one-host tmpfs ordinary-Git feasibility; not production/history/quota proof','staleClaimRejected':'Any 1.6GB raw-archive claim is false for this fixed closure; authority is 129833713 raw unique bytes.'},
  'render':{'fileCount':563,'bytes':2129784,'renderElapsedSeconds':1.4841489950194955,'renderPeakRssKiB':11560,'checkElapsedSeconds':0.0255,'checkPeakRssKiB':11592,'config':{'bytes':76,'sha256':'9a591cbdb924a588f69f88170e52be8d52b0d08e2261dc1b1b0732171e35ebcc'},'downloads':{'bytes':154344,'sha256':'9c0cb103f61caeb95a52f76fc3cd479d94c261aef86a7b5d96711e902e26fe94'},'release':{'bytes':459017,'sha256':'2be183106bc9e055a7a1167edad498dae92adbe09c752d9b7927c9ee90542354'},'sparseRows':555,'sparseJsonRecords':747,'largestSparseRowBytes':max_sparse[0],'largestSparseRowPath':'/'+max_sparse[1],'retainedCrateRoutes':3,'providerAdapterFiles':2,'canonicalFileInventorySha256':hashlib.sha256(render_inventory_bytes).hexdigest(),'routePathListSha256':'3a6b331778b51b4540ce0bd5d6448c6642808977e1dedd1d0648bea62c7cbdea'},
  'currentPublicRoutes':{'fixedRenderer200':563,'extraPublished200':3,'canonicalSameHostDownload404':747,'legacyDownload307':747,'legacyPublicAdmin200':2,'allRustInventoryRows':2062,'targetDynamicDescriptors':2055,'legacyRedirectBodySha256':EMPTY_SHA,'legacyRedirectCacheControl':'no-store'},
  'gitStorage':git_summary,
  'cargo':{'lockVersion':4,'lockSha256':'c570ebeb47fa360f060d282286d4759836c6fde3af1f0b7f35e1ecf7dde0d124','lockPackageCount':174,'externalPackageCount':172,'externalSource':'sparse+https://rust.pkg.re/','workspaceRoots':['pkgre-rust 0.5.0','pkgre-proxy 0.2.0'],'roots':{'pkgre-rust':{'packagesIncludingRoot':55,'thirdPartyPackages':54,'selectedPackageFeaturePairs':113},'pkgre-proxy':{'packagesIncludingRoot':155,'thirdPartyPackages':154,'selectedPackageFeaturePairs':305},'workspaceUnion':{'packagesIncludingRoots':174,'thirdPartyPackages':172,'selectedPackageFeaturePairs':347}},'cargoConfig':{'cratesIoReplacedWith':'disabled-crates-io','defaultRegistry':'pkgre','offlineExplicit':False,'pkgreIndex':'sparse+https://rust.pkg.re/'},'closureFixtureSha256':sha(CLOSURE)},
  'toolchainAndTests':{'rustToolchain':'1.95.0','cargo':'1.95.0 (f2d3ce0bd)','rustc':'1.95.0 (59807616e)','workspaceRustVersion':'1.85','rustNixDrv':'/nix/store/6c2aa3pzzdm5k5nalk1crdcinynwwvzj-pkgre-rust-0.5.0.drv','rustNixOutput':'/nix/store/bqiaxi9lhg0a8mva3qwmnys70mhnx1wk-pkgre-rust-0.5.0','proxyNixDrv':'/nix/store/a0950b3qzcanrcalvwlp1b45nrya39xn-pkgre-proxy-0.2.0.drv','proxyNixOutput':'/nix/store/1a25f3q7qvdxgcbcjs267h395xzy4016-pkgre-proxy-0.2.0','flakeInputs':{'nixpkgs':{'rev':'2c423e03bbafcff28bfadc6781a4a8257f205cb5','narHash':'sha256-dt4WdcvsA8/RCe+VZZwqU0X+XMM3wBbGCWA0/sFWzGo='},'rust-overlay':{'rev':'fd2ebb9cc4323d0c5a1336138dab5c3c5a5d8bd9','narHash':'sha256-YT4Fs2k7bi+7YzuLt93EtIRgjpwHK5ZfsQEIh5dEQSk='}},'nixAttrs':['.#rust','.#indexer','.#proxy','.#download-serve'],'missingNixAttr':'.#rust-serve','workspaceTest':{'command':'nix develop <fixed-source-snapshot> -c cargo test --workspace --locked','passed':173,'failed':0,'elapsedSeconds':15.915},'nixPackageChecks':['cargo test --package <name> --frozen','cargo clippy --package <name> --all-targets --frozen -- -D warnings']}
 },
 'planRequirements':{'canonicalRoutes':['/config.json','/<Cargo lowercase sparse-row path>','/r/<registry>/config.json (only additional explicit registry)','/r/<registry>/<sparse-row path> (only additional explicit registry)','/release.json','/downloads.json','/v1/<registry>/<crate>/<version>/<sha256>','/crates/<sha256>.crate'],'dynamicConfig':{'stateContract':'state-contract-v1','redirectMarkerSchema':None},'contentTypes':{'json':'application/json; charset=utf-8','sparse':'text/plain; charset=utf-8','archive':'application/octet-stream'},'compatibility':'typed closed 307 to catalog-locked destination; zero body','bodyMode':'verified archive bytes at same /v1 identity; /crates remains retained body','rootMainAllowedBecauseObservedRegistryCount':1},
 'blockers':blockers,
 'artifactRows':{'admissions.jsonl':len(admission_rows),'catalog-homes.jsonl':len(homes),'rendered-routes.jsonl':len(render_rows),'versions-downloads.jsonl':len(version_rows)}
}

dump_jsonl(OUT/'catalog-homes.jsonl',homes)
dump_jsonl(OUT/'admissions.jsonl',admission_rows)
dump_jsonl(OUT/'versions-downloads.jsonl',version_rows)
dump_jsonl(OUT/'rendered-routes.jsonl',render_rows)
dump(OUT/'inventory.json',inventory)

report=f'''# Rust D0 catalog+render inventory

Status:artifact-complete for fixed Rust catalog/render scope;broader plan D0 remains blocked | catalog:`{CAT_COMMIT}` | implementation/render:`{IMPL_COMMIT}` | repository mutation:none

## Classification

- Observed facts:fixed-commit catalog bytes;fixed-render output;point-in-time public route evidence;committed archive rehearsal;validated Cargo/Nix evidence. Machine source:`inventory.json.observedFacts`+JSONL rows.
- Plan requirements:normative target routes/MIME/state fields copied into `inventory.json.planRequirements`;not claimed current.
- Proposals:none promoted here. Resource/time proposals remain separate and require operator+reviewer approval.

## Exact inventory

| Field | Result |
|---|---|
| Registry | schema=4;exactly one `main`;index=`sparse+https://rust.pkg.re/`;download=`https://dl.rust.pkg.re/v1/main/{{crate}}/{{version}}/{{sha256-checksum}}`;Cargo=1.95.0 |
| Categories/homes | 9 categories;911 permanent homes;555 names have versions;356 reserved empty homes |
| Versions/graph | 747 active;0 removed;5,518 dependency edges;744 crates.io+3 Git-tag;full source row retained per `versions-downloads.jsonl` |
| Admissions | 1 batch;3 identities;complete manifest+candidate evidence in `admissions.jsonl` |
| Catalog hashes | `main.lock`=075a97b50ca504492fa3c133987b9e61f8c270b95a36819e2b56835c9837cd54/320,545B;`downloads.json`=9c0cb103f61caeb95a52f76fc3cd479d94c261aef86a7b5d96711e902e26fe94/154,344B |
| Current catalog bodies | 3/747 `.crate`;229,784B;744 bodies absent from source tree |
| Fixed render | 563 files/2,129,784B;555 sparse rows/747 JSON records;3 archives;3 JSON docs;2 provider adapters |
| Largest render | `release.json`=459,017B;largest sparse `/we/b-/web-sys`=107,745B |
| Core hashes | config=9a591cbdb924a588f69f88170e52be8d52b0d08e2261dc1b1b0732171e35ebcc;downloads=9c0cb103f61caeb95a52f76fc3cd479d94c261aef86a7b5d96711e902e26fe94;release=2be183106bc9e055a7a1167edad498dae92adbe09c752d9b7927c9ee90542354 |
| Current public route closure | 563 fixed renderer routes+3 extra published routes=566 `rust.pkg.re` 200;747 same-host `/v1` 404;747 `dl.rust.pkg.re` 307;2 legacy admin 200;2,062 Rust inventory rows |
| Cargo closure | lock v4;174 packages;172 third-party,all exact `sparse+https://rust.pkg.re/`;indexer=55 packages/113 feature pairs;proxy=155/305;full rows=`cargo-closure.json` |
| Toolchain/tests | rustc/Cargo 1.95.0;`.#rust`+`.#proxy` exact drv/out in `inventory.json`;173 workspace tests passed;no `.#rust-serve` yet |

## Authoritative archive rehearsal cross-check

Committed authority:`/home/dev0/repos/pkgre@1d44dfeaeafef2b1a5341c13bf73647dcbc925ec/fixtures/d0-v1/archive-git-rehearsal`;its `SHA256SUMS` passed. Exact closure=747 routes=747 unique hashes=747 verified archives;failures=0;raw unique bytes=`129,833,713`;logical route bytes=`129,833,713`;largest=`9,679,450B` (`f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483`). `download-summary.json` SHA-256=`53e1a700d3c7ca0d9314bf2364e0387477388c25a6bcce386af28c602a63c68c`;`git-metrics.json`=`a79b6d9f617e6a4b45727205b104f29b33c7bca009513f15c8f00e67f4804e00`;`download-results.json`=`76c01873b2c30caf7c631acf6fd7f16da0336172cc5ebaca5a21fd408939b72b`.

Ordinary-Git tmpfs measurement:loose repo apparent=136,370,257B;packed repo apparent/allocated=129,497,688/129,585,152B;bare repo apparent/allocated=129,367,206/129,429,504B;checkout repo+tree apparent=259,463,809B;allocated=261,058,560B;strict fsck+checkout rehash passed. This proves one-host current-closure feasibility only. It does not prove append-only history growth,provider/Rain quota,production filesystem behavior,or backup/restore. Any stale `1.6GB raw archives` claim is rejected;fixed-basis authority is exactly `129,833,713B`.

## Render/routes+headers

`rendered-routes.jsonl` enumerates all 563 fixed bytes with path,length,SHA-256,current observed content type/semantic headers,planned dynamic MIME,and D8–D14 mapping. Current Pages sparse MIME=`application/octet-stream`;plan target=`text/plain; charset=utf-8`,an intentional D1 fixture decision. JSON currently=`application/json; charset=utf-8`;archives=`application/octet-stream`. Current Pages validators/cache headers are deployment-derived;plan requires deterministic source-owned validators. `versions-downloads.jsonl` enumerates all 747 identities,full source record,archive byte measurement,retrieval URL,current body presence,and exact observed legacy 307/canonical 404.

## Git/storage+dependency facts

Catalog basis is clean/current locally;Git object format=SHA-1/40-hex;773 tree entries;763 unique blobs/1,958,607B;canonical tree SHA-256=`ebb632e21d7553d46da4b3db0c4dac5be1cdd6ec2b51a1c21a3c59e511492355`;strict full fsck/connectivity passed in cited D0 storage evidence;no shallow/alternates/grafts/promisor/replace/gitlinks/LFS/filter/tree-symlink finding. This is a non-bare development checkout with SSH origin and does not prove production bare mirror ownership/quota/layout.

Current exact Cargo closure is frozen in `cargo-closure.json`;all 172 third-party nodes use curated `rust.pkg.re`. Current `.cargo/config.toml` replaces crates.io and has `offlineExplicit=false`;the operator-approved plan amendment makes `[net] offline=true` plus its self-host/cold-replay proof a mandatory pre-D5 gate,not a D0 mutation or blocker. The planned server should reuse admitted Axum/Tokio/tracing/anyhow utilities and remove `reqwest`/TLS/client closure;the exact future lock diff is not an observed fact and remains blocked until authorized implementation.

## Blocking unknowns

''' + '\n'.join(f"{i+1}. `{b['id']}`:{b['fact']}" for i,b in enumerate(blockers)) + '''

## Files+validation

- `inventory.json`:bounded summary;observed/plan/proposal separation;all counts,hashes,toolchain,Nix,Git,archive facts+blockers.
- `catalog-homes.jsonl`:911 permanent home declarations including empty reservations,mirror versions,publish tags/source.
- `admissions.jsonl`:3 admitted identities with full candidate evidence.
- `versions-downloads.jsonl`:747 active identities with full retained source row+download/archive/current route evidence.
- `rendered-routes.jsonl`:563 fixed rendered representations.
- `cargo-closure.json`:feature-selected exact lock closure.
- `validation.json`:machine validation results.
- `SHA256SUMS`:all final artifacts except itself.
- `build_inventory.py`:read-only reconstruction;writes only this artifact directory.

Exact final validation:`python3 -m json.tool inventory.json cargo-closure.json validation.json`;parse every JSONL line;assert row counts 911/3/747/563;assert fixed bases+catalog/rehearsal/render invariants;`sha256sum -c SHA256SUMS`;recheck both project repositories with `git status --porcelain=v2`. No network/provider/deployment operation and no project repository write occurred.
'''
(OUT/'REPORT.md').write_text(report)

# Validate before creating validation.json and checksums.
checks=[]
def check(name,cond,detail=None): checks.append({'name':name,'pass':bool(cond),'detail':detail}); assert cond
for fn in ['inventory.json','cargo-closure.json']:
    json.load(open(OUT/fn)); check('json:'+fn,True)
for fn,n in [('catalog-homes.jsonl',911),('admissions.jsonl',3),('versions-downloads.jsonl',747),('rendered-routes.jsonl',563)]:
    rows=[json.loads(x) for x in (OUT/fn).read_text().splitlines()]; check('jsonl:'+fn,len(rows)==n,{'actual':len(rows),'expected':n})
check('archive-authority',summary['raw_unique_bytes']==129833713 and summary['verified_unique_count']==747)
check('render-count-bytes',len(render_rows)==563 and render_bytes==2129784)
check('catalog-counts',len(homes)==911 and len(version_rows)==747 and dep_edges==5518)
check('catalog-repo-clean',git(CAT,'status','--porcelain=v2')=='')
check('implementation-repo-clean',git('/home/dev0/repos/pkgre','status','--porcelain=v2')=='')
validation={'schema':'pkgre-d0-rust-inventory-validation-v1','result':'PASS','checks':checks,'projectRepositoriesModified':False,'rowCounts':inventory['artifactRows']}
dump(OUT/'validation.json',validation)

files=['REPORT.md','inventory.json','catalog-homes.jsonl','admissions.jsonl','versions-downloads.jsonl','rendered-routes.jsonl','cargo-closure.json','validation.json','build_inventory.py']
with open(OUT/'SHA256SUMS','w') as f:
    for fn in files: f.write(f'{sha(OUT/fn)}  {fn}\n')
print(json.dumps({'output':str(OUT),'files':{fn:{'bytes':(OUT/fn).stat().st_size,'sha256':sha(OUT/fn)} for fn in files+['SHA256SUMS']},'rows':inventory['artifactRows'],'result':'PASS'},sort_keys=True,indent=2))
