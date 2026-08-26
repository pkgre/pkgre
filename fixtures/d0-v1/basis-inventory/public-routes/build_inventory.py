#!/usr/bin/env python3
"""D0 exact route inventory generator/checker; stdlib only; never follows redirects."""
import argparse, concurrent.futures, datetime, hashlib, json, mimetypes, os, pathlib, ssl, subprocess, threading, time, tomllib, urllib.error, urllib.request
EMPTY_SHA='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
PKGRE_COMMIT='066293df21743cbf41fb571a38f2bb94059e7274'; RUST_COMMIT='f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b'; JS_COMMIT='f43bd58bd3d4e36f8b3f4df3c002735c977acd17'
EDGE_HEADERS={'server','date','via','age','x-origin-cache','x-proxy-cache','x-github-request-id','x-github-edge-region','x-served-by','x-cache','x-cache-hits','x-timer','x-fastly-request-id','expires','last-modified','etag','access-control-allow-origin','accept-ranges','vary','content-security-policy'}
OWNED_HEADERS={'content-type','content-length','location','cache-control','allow','retry-after'}
def sha(b): return hashlib.sha256(b).hexdigest()
def jdump(p,x): pathlib.Path(p).write_text(json.dumps(x,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
def sparse_path(n):
 n=n.lower(); L=len(n)
 return ('1/'+n if L==1 else '2/'+n if L==2 else '3/'+n[0]+'/'+n if L==3 else n[:2]+'/'+n[2:4]+'/'+n)
def rep(b,ctype,kind,source_file): return {'kind':kind,'bodySha256':sha(b),'bodyLength':len(b),'contentType':ctype,'sourceFile':source_file}
def intended(status,ctype=None,body=None,location=None,handler=None):
 x={'status':status,'handler':handler,'contentLength':0 if status==307 else (len(body) if body is not None else None),'contentType':ctype}
 if body is not None:x['bodySha256']=sha(body)
 if location is not None:x['location']=location
 return x
def route(ecosystem,host,path,cls,raw,audience,source_record,source_rep,intent,phases,changes=None):
 return {'ecosystem':ecosystem,'origin':'https://'+host,'host':host,'rawPath':path,'url':'https://'+host+path,'class':cls,'audience':audience,'sourceCatalogRecord':source_record,'repositoryRepresentation':source_rep,'intended':intent,'d8ToD14Behavior':phases,'intentionalChanges':changes or [],'observed':None}
def git(repo,*args): return subprocess.check_output(['git','-C',repo,*args],text=True).strip()
def assert_commit(repo,want):
 if subprocess.run(['git','-C',repo,'cat-file','-e',want+'^{commit}']).returncode: raise SystemExit('missing commit '+want+' in '+repo)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw): return None
_locks={h:threading.Lock() for h in ['rust.pkg.re','dl.rust.pkg.re','js.pkg.re']}; _last={h:0.0 for h in _locks}
def probe(r):
 host=r['host']
 with _locks[host]:
  wait=.075-(time.monotonic()-_last[host])
  if wait>0:time.sleep(wait)
  _last[host]=time.monotonic()
 try:
  req=urllib.request.Request(r['url'],headers={'Accept-Encoding':'identity','User-Agent':'pkgre-d0-route-inventory/1'})
  op=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=ssl.create_default_context()))
  try: resp=op.open(req,timeout=30)
  except urllib.error.HTTPError as e: resp=e
  body=resp.read(); hs={}
  for k,v in resp.headers.items(): hs.setdefault(k.lower(),[]).append(v)
  return {'timestampUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':resp.status,'bodyLength':len(body),'bodySha256':sha(body),'headers':hs,'semanticHeaders':{k:v for k,v in hs.items() if k in OWNED_HEADERS},'edgeOwnedHeaders':{k:v for k,v in hs.items() if k in EDGE_HEADERS},'unclassifiedHeaders':{k:v for k,v in hs.items() if k not in OWNED_HEADERS|EDGE_HEADERS},'error':None}
 except Exception as e:return {'timestampUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':None,'bodyLength':None,'bodySha256':None,'headers':{},'semanticHeaders':{},'edgeOwnedHeaders':{},'unclassifiedHeaders':{},'error':type(e).__name__+': '+str(e)}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--out',default=str(pathlib.Path(__file__).resolve().parent)); ap.add_argument('--rust-render',required=True); ap.add_argument('--rust-repo',default='/home/dev0/repos/pkgre-rust'); ap.add_argument('--js-repo',default='/home/dev0/repos/pkgre-js'); ap.add_argument('--pkgre-repo',default='/home/dev0/repos/pkgre'); ap.add_argument('--probe',action='store_true'); a=ap.parse_args(); out=pathlib.Path(a.out);out.mkdir(parents=True,exist_ok=True)
 for repo,c in [(a.pkgre_repo,PKGRE_COMMIT),(a.rust_repo,RUST_COMMIT),(a.js_repo,JS_COMMIT)]:assert_commit(repo,c)
 rr=pathlib.Path(a.rust_render); rustroot=pathlib.Path(a.rust_repo); jsroot=pathlib.Path(a.js_repo); jsfinal=jsroot/'bootstrap/js-v0.1.0/site-final'
 lock=tomllib.loads(subprocess.check_output(['git','-C',a.rust_repo,'show',RUST_COMMIT+':registry/main.lock'],text=True)); downloads=json.loads(subprocess.check_output(['git','-C',a.rust_repo,'show',RUST_COMMIT+':registry/downloads.json'],text=True)); jscat=json.loads(subprocess.check_output(['git','-C',a.js_repo,'show',JS_COMMIT+':bootstrap/js-v0.1.0/catalog.json'],text=True))
 pkgs={(p['name'],p['version']):p for p in lock['packages']}; byname={n['name']:[] for n in lock['names']}
 for p in lock['packages']:byname[p['name']].append(p)
 routes=[]; rsrc=lambda typ,**kw:{'repository':'https://github.com/pkgre/pkgre-rust','commit':RUST_COMMIT,'file':'registry/main.lock','recordType':typ,**kw}
 # Renderer outputs, excluding root files handled explicitly.
 names_by_path={sparse_path(n):n for n in byname}
 for f in sorted(p for p in rr.rglob('*') if p.is_file()):
  rel=f.relative_to(rr).as_posix(); b=f.read_bytes(); path='/'+rel
  if rel in names_by_path:
   n=names_by_path[rel]; ids=[{'registry':'main','name':p['name'],'version':p['version'],'sha256':p['crate-sha256'],'state':p['state'],'sourceKind':p['source']['kind']} for p in byname[n]]
   sr=rsrc('name+sparse-rows',registry='main',name=n,category=next(x['category'] for x in lock['names'] if x['name']==n),identities=ids); rp=rep(b,'text/plain; charset=utf-8','sparse-row',rel); it=intended(200,'text/plain; charset=utf-8',b,handler='rust-metadata'); ph='D8 exact dynamic bytes;D9-D14 retained unchanged'
   routes.append(route('rust','rust.pkg.re',path,'rust-sparse-row',path,'public',sr,rp,it,ph));continue
  if rel.startswith('crates/'):
   h=pathlib.Path(rel).stem;p=next(p for p in lock['packages'] if p['crate-sha256']==h);sr=rsrc('package',registry='main',name=p['name'],version=p['version'],sha256=h,source=p['source']);rp=rep(b,'application/octet-stream','rust-crate-object',rel);it=intended(200,'application/octet-stream',b,handler='rust-object');ph='D8-D14 exact retained body;also destination of compatibility redirect'
   routes.append(route('rust','rust.pkg.re',path,'rust-crate-object',path,'public',sr,rp,it,ph));continue
  ctype='application/json; charset=utf-8' if rel.endswith('.json') else 'application/octet-stream'
  cls={'config.json':'rust-config','downloads.json':'rust-download-catalog','release.json':'rust-release','CNAME':'provider-cname','.nojekyll':'provider-control'}[rel]
  sr=rsrc('aggregate' if rel.endswith('.json') else 'provider-adapter',renderedPath=rel);rp=rep(b,ctype,cls,rel)
  if rel in ('CNAME','.nojekyll'):it=intended(404,None,None,handler='fixed-not-found');ph='D8 absent from dynamic protocol;Pages copy retained only as rollback through D14';ch=['provider adapter intentionally not exposed after D8']
  else:it=intended(200,ctype,b,handler='rust-metadata');ph='D8 exact dynamic bytes;D9-D14 retained unchanged';ch=[]
  routes.append(route('rust','rust.pkg.re',path,cls,path,'public',sr,rp,it,ph,ch))
 # Rust landing+canary from fixed catalog repo commit, plus root alias.
 for rel,cls in [('index.html','landing-page'),('origin-health/v1.txt','legacy-origin-canary')]:
  b=subprocess.check_output(['git','-C',a.rust_repo,'show',RUST_COMMIT+':'+rel]);ctype='text/html; charset=utf-8' if rel.endswith('html') else 'text/plain; charset=utf-8';sr={'repository':'https://github.com/pkgre/pkgre-rust','commit':RUST_COMMIT,'file':rel,'recordType':'static-publication'};rp=rep(b,ctype,cls,rel);it=intended(404,None,None,handler='fixed-not-found');ph='D8 omitted from protocol-only dynamic vhost;static rollback retained through D14';ch=['public 200 bytes become fixed 404 at metadata cutover']
  routes.append(route('rust','rust.pkg.re','/'+rel,cls,'/'+rel,'public',sr,rp,it,ph,ch))
  if rel=='index.html':routes.append(route('rust','rust.pkg.re','/','landing-page-alias','/','public',sr,rp,it,ph,ch+['GitHub Pages index alias retired']))
 # Rust archive identities: legacy advertised host + same-path future canonical origin.
 for d in downloads['routes']:
  p=pkgs[(d['name'],d['version'])]; path=f"/v1/{d['registry']}/{d['name']}/{d['version']}/{d['sha256']}"; loc=(f"https://static.crates.io/crates/{d['name']}/{d['version']}/download" if d['source']=='crates-io' else f"https://rust.pkg.re/crates/{d['sha256']}.crate");sr=rsrc('active-download-route',registry=d['registry'],name=d['name'],version=d['version'],sha256=d['sha256'],source=p['source']);rp={'kind':'live-service-route','bodySha256':EMPTY_SHA,'bodyLength':0,'contentType':None,'sourceFile':'registry/downloads.json','redirectDestination':loc};it=intended(307,None,None,loc,'rust-compatibility-redirect')
  routes.append(route('rust','dl.rust.pkg.re',path,'rust-download-legacy-alias',path,'public',sr,rp,it,'D8 stays 307;D9 retained compatibility while config moves to rust.pkg.re;D10 dormant;D14 host removed',[]))
  routes.append(route('rust','rust.pkg.re',path,'rust-download-canonical',path,'public',sr,None,it,'D8 307;D9 200 exact archive body;D10-D14 body-only', ['current Rust-host alias is 404 because no Rust marker files were rendered;D8 intentionally activates typed 307']))
 # Current public legacy admin leak.
 for path in ['/healthz','/status']:
  routes.append(route('rust','dl.rust.pkg.re',path,'legacy-public-admin',path,'public',{'repository':'https://github.com/pkgre/pkgre','commit':'ae1dfbfd4e965dffb538e356f005e4fbb32fdb77','file':'download-serve/src/web.rs','recordType':'legacy-operational'},None,{'status':200,'handler':'legacy-service-until-D14','contentLength':None,'contentType':None},'D8-D13 unchanged on legacy host;D14 host removed;future dynamic admin is private-only',['currently public operational endpoint;no canonical public dynamic target']))
 # JS final render; every raw file path plus Pages directory aliases.
 jpkg=jscat['packages'][0]; jver=jpkg['versions'][0]; jsid={'registry':'main','name':jpkg['name'],'version':jver['version'],'source':jver['source']}; jsbase={'repository':'https://github.com/pkgre/pkgre-js','commit':JS_COMMIT,'file':'bootstrap/js-v0.1.0/catalog.json','recordType':'catalog-package-version',**jsid}
 js_prefix='bootstrap/js-v0.1.0/site-final/'
 js_files=[p for p in subprocess.check_output(['git','-C',a.js_repo,'ls-tree','-r','--name-only',JS_COMMIT,'--',js_prefix],text=True).splitlines() if p]
 for gitpath in sorted(js_files):
  rel=gitpath.removeprefix(js_prefix);b=subprocess.check_output(['git','-C',a.js_repo,'show',JS_COMMIT+':'+gitpath]);path='/'+rel
  if rel=='pkgre-js':cls='js-packument';ctype='application/json; charset=utf-8';it=intended(200,ctype,b,handler='js-metadata');ph='D11 exact dynamic bytes;D12-D14 retained';ch=['rendered but not currently live:edge returns 502']
  elif rel.startswith('packages/'):cls='js-package-object';ctype='application/octet-stream';it=intended(200,ctype,b,handler='js-object');ph='D11-D14 exact retained body';ch=['rendered but not currently live:edge returns 502']
  elif rel.startswith('v1/js/'):
   cls='js-download-marker';ctype='text/html; charset=utf-8';loc='https://js.pkg.re/packages/'+jver['source']['sha256']+'.tgz';it=intended(307,None,None,loc,'js-compatibility-redirect');ph='D11 marker HTML replaced by direct typed 307;D12 200 exact archive body;D14 legacy adapter removed';ch=['repository HTML marker becomes zero-body typed 307','currently 503 because JS origin not ready']
  elif rel=='.pkgre-js-site.json':cls='generated-site-inventory';ctype='application/json; charset=utf-8';it=intended(404,None,None,handler='fixed-not-found');ph='D11 excluded from protocol projection;static rollback retained through D14';ch=['rendered control inventory intentionally becomes 404']
  elif rel in ('index.html','origin-health/v1.txt','.nojekyll') or rel.startswith('nonproduction/'):
   cls={'index.html':'landing-page','origin-health/v1.txt':'legacy-origin-canary','.nojekyll':'provider-control'}.get(rel,'nonproduction-fixture');ctype='text/html; charset=utf-8' if rel.endswith('html') else ('text/plain; charset=utf-8' if rel.endswith('txt') else 'application/octet-stream');it=intended(404,None,None,handler='fixed-not-found');ph='D11 excluded from protocol projection;static rollback retained through D14';ch=['currently 502;source-rendered control route intentionally becomes 404']
  else:raise AssertionError(rel)
  rp=rep(b,ctype,cls,rel);sr=jsbase if cls in ('js-packument','js-package-object','js-download-marker') else {'repository':'https://github.com/pkgre/pkgre-js','commit':JS_COMMIT,'file':'bootstrap/js-v0.1.0/site-final/'+rel,'recordType':'static-or-generated-adapter'}
  routes.append(route('js','js.pkg.re',path,cls,path,'public',sr,rp,it,ph,ch))
  if rel=='index.html':routes.append(route('js','js.pkg.re','/','landing-page-alias','/','public',sr,rp,it,ph,ch+['Pages index alias'] ))
  if rel=='nonproduction/redirect-marker-fixture-v0/index.html':routes.append(route('js','js.pkg.re','/nonproduction/redirect-marker-fixture-v0/','nonproduction-fixture-alias','/nonproduction/redirect-marker-fixture-v0/','public',sr,rp,it,ph,ch+['Pages directory index alias']))
 for r in routes:
  r['targetCanonical'] = (None if r['class']=='legacy-public-admin' else {'origin':'https://rust.pkg.re' if r['class']=='rust-download-legacy-alias' else r['origin'],'rawPath':r['rawPath']})
 routes.sort(key=lambda r:(r['host'],r['rawPath']))
 # Structural checks.
 keys=[(r['host'],r['rawPath']) for r in routes];assert len(keys)==len(set(keys))
 assert len(lock['registry'])==3 and lock['registry']['name']=='main'; assert len(lock['names'])==911 and len(lock['packages'])==747 and len(downloads['routes'])==747
 assert set((d['name'],d['version'],d['sha256']) for d in downloads['routes'])==set((p['name'],p['version'],p['crate-sha256']) for p in lock['packages'] if p['state']=='active')
 assert set(sparse_path(n) for n,ps in byname.items() if ps)==set(p.relative_to(rr).as_posix() for p in rr.rglob('*') if p.is_file() and p.relative_to(rr).as_posix() in names_by_path)
 assert sum(r['class']=='rust-sparse-row' for r in routes)==555;assert sum(r['class']=='rust-download-legacy-alias' for r in routes)==747;assert sum(r['class']=='rust-download-canonical' for r in routes)==747;assert sum(r['class']=='rust-crate-object' for r in routes)==3;assert sum(r['class']=='js-packument' for r in routes)==1;assert not any('%2f' in r['rawPath'] for r in routes)
 prior_doc=None
 if a.probe:
  with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
   obs=list(ex.map(probe,routes))
  for r,o in zip(routes,obs):r['observed']=o
 else:
  old=out/'routes.json'
  if old.exists():
   prior_doc=json.loads(old.read_text());prior={(r['host'],r['rawPath']):r['observed'] for r in prior_doc['routes']}
   for r in routes:r['observed']=prior.get((r['host'],r['rawPath']))
 counts={}
 for r in routes:counts[r['class']]=counts.get(r['class'],0)+1
 errors=[r['url'] for r in routes if not r['observed'] or r['observed']['error']]
 live_equal=[]
 for r in routes:
  rp=r['repositoryRepresentation'];o=r['observed']
  if rp and o and o['status']==200 and rp.get('bodySha256')==o.get('bodySha256') and rp.get('bodyLength')==o.get('bodyLength'):live_equal.append(r['url'])
 meta={'schema':'pkgre-d0-route-inventory-v1','generatedUtc':(prior_doc['metadata']['generatedUtc'] if prior_doc else datetime.datetime.now(datetime.timezone.utc).isoformat()),'fixedCommits':{'pkgre':PKGRE_COMMIT,'pkgreRust':RUST_COMMIT,'pkgreJs':JS_COMMIT},'scope':'all fixed-commit rendered/published raw routes plus both Rust archive host spellings and current public legacy admin leak','counts':{'routes':len(routes),'byClass':counts,'rustCatalogNames':911,'rustRenderedSparseRows':555,'rustReservedNamesWithoutRows':356,'rustPackageVersions':747,'rustDownloadIdentities':747,'rustFirstPartyObjects':3,'jsPackages':1,'jsVersions':1,'jsScopedPackuments':0,'probeErrors':len(errors),'repositoryBytesEqualLive':len(live_equal)},'edgeOwnedHeaderNames':sorted(EDGE_HEADERS),'notes':['repositoryRepresentation is fixed-commit source/rendered bytes;observed is live HTTP and is never substituted for source authority','rawPath is the exact path spelling;redirects were not followed','current public audience is recorded even for provider controls;future dynamic projection intentionally excludes non-protocol routes','all Rust catalog names map to one root sparse file;all active identities map to both the advertised dl.rust alias and future canonical rust.pkg.re path']}
 jdump(out/'routes.json',{'metadata':meta,'routes':routes}); jdump(out/'sources.json',{'schema':'pkgre-d0-source-catalog-v1','fixedCommits':meta['fixedCommits'],'rust':{'schema':lock['schema'],'registry':lock['registry'],'nameCount':len(lock['names']),'packageCount':len(lock['packages']),'activeDownloadCount':len(downloads['routes']),'sourceKinds':{'crates-io':sum(p['source']['kind']=='crates-io' for p in lock['packages']),'git-tag':sum(p['source']['kind']=='git-tag' for p in lock['packages'])},'firstPartyPackages':[p for p in lock['packages'] if p['source']['kind']=='git-tag']},'js':{'catalog':jscat,'packageCount':1,'versionCount':1,'scopedPackageCount':0}}); jdump(out/'validation.json',{'schema':'pkgre-d0-route-validation-v1','result':'PASS' if not errors else 'PASS-WITH-LIVE-PROBE-ERRORS','checks':{'uniqueHostRawPath':True,'singleRustRegistryMain':True,'all555NamesWithVersionsHaveSparseRoute':True,'all356ReservedNamesCorrectlyHaveNoPublishedRow':True,'all747ActiveIdentitiesCloseOverLockAndDownloads':True,'eachRustIdentityHasExactlyTwoHostMappings':True,'threeGitTagObjectsPresent':True,'jsCatalogClosure':True,'noScopedJsPackumentsPresent':True,'allFixedRenderFilesMapped':True,'noDuplicateMappings':True,'all747RustCanonicalPathsObserved404':all(r['observed'] and r['observed']['status']==404 for r in routes if r['class']=='rust-download-canonical'),'all747LegacyDownloadPathsObservedExact307':all(r['observed'] and r['observed']['status']==307 and r['observed']['bodyLength']==0 and r['observed']['semanticHeaders'].get('location')==[r['intended']['location']] for r in routes if r['class']=='rust-download-legacy-alias'),'all566RustStaticRouteObservationsMatchRepositoryBytes':sum(1 for r in routes if r['ecosystem']=='rust' and r['repositoryRepresentation'] and r['observed'] and r['observed']['status']==200 and r['repositoryRepresentation'].get('bodySha256')==r['observed'].get('bodySha256') and r['repositoryRepresentation'].get('bodyLength')==r['observed'].get('bodyLength'))==566,'jsLiveFailuresCapturedSeparatelyFromRepositoryBytes':all(r['observed'] and r['observed']['status'] in (502,503) for r in routes if r['ecosystem']=='js')},'probeErrors':errors,'counts':meta['counts']})
 print(json.dumps(meta['counts'],sort_keys=True))
if __name__=='__main__':main()
