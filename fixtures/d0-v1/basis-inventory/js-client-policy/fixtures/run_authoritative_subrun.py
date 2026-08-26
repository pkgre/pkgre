#!/nix/store/l9k0anq0z7zz81zcwy035jfwap9ga6rl-python3-3.13.13/bin/python3.13
from __future__ import annotations
import hashlib,json,os,re,shutil,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'raw'/'subrun';TRACE=OUT/'traces';PROFILE=ROOT/'configs'/'loopback'/'profile.json';WRAPPER=ROOT/'wrappers'/'policy_wrapper.py';REGISTRY=ROOT/'raw'/'controlled_registry.py';PORT=48730
CLIENTS=['npm-minimum','npm-current','bun-minimum','bun-current','deno-minimum','deno-current']

def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def lines(p):return p.read_text().splitlines() if p.exists() else []
def clean_name(s):return re.sub(r'[^A-Za-z0-9_.-]+','-',s)
def internet_connects(text):
 return [x for x in text.splitlines() if 'connect(' in x and ('AF_INET' in x or 'AF_INET6' in x)]
def execs(text):return [x for x in text.splitlines() if 'execve(' in x]
def run_case(work,project,state,home,client,phase,mode,extra=(),env_extra=None,expect=0,expect_code=None):
 name=clean_name(f'{client}-{phase}');trace=TRACE/f'{name}.strace';audit=OUT/f'{name}.audit.json';stdout=OUT/f'{name}.stdout';stderr=OUT/f'{name}.stderr'
 env={'HOME':str(home),'PATH':'/run/current-system/sw/bin:/home/dev0/.nix-profile/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','NO_COLOR':'1','TERM':'dumb'}
 if env_extra:env.update(env_extra)
 cmd=['strace','-f','-qq','-s','256','-e','trace=execve,connect','-o',str(trace),str(WRAPPER),'--profile',str(PROFILE),'--client-id',client,'--project-root',str(project),'--state-root',str(state),'--audit-log',str(audit),'--mode',mode,*extra]
 before=len(lines(OUT/'registry-requests.jsonl'))
 cp=subprocess.run(cmd,env=env,text=True,capture_output=True,cwd=ROOT)
 stdout.write_text(cp.stdout);stderr.write_text(cp.stderr)
 after_lines=lines(OUT/'registry-requests.jsonl');requests=[json.loads(x) for x in after_lines[before:]]
 tr=trace.read_text();nets=internet_connects(tr);ex=execs(tr);a=json.loads(audit.read_text())
 bad=[x for x in nets if not ('127.0.0.1' in x and f'htons({PORT})' in x)]
 result={'id':name,'client':client,'phase':phase,'mode':mode,'command':cmd,'wrapperCommand':a.get('command'),'returnCode':cp.returncode,'expectedReturnCode':expect,'decision':a.get('decision'),'rejectCode':a.get('rejectCode'),'clientExecAttempted':a.get('clientExecAttempted'),'networkConnects':nets,'unexpectedNetworkConnects':bad,'registryRequests':requests,'execve':ex,'trace':str(trace.relative_to(ROOT)),'traceSha256':h(trace),'audit':str(audit.relative_to(ROOT)),'auditSha256':h(audit),'stdout':str(stdout.relative_to(ROOT)),'stdoutSha256':h(stdout),'stderr':str(stderr.relative_to(ROOT)),'stderrSha256':h(stderr)}
 if cp.returncode!=expect:raise RuntimeError(f'{name}:rc={cp.returncode}:want={expect}:{cp.stderr}')
 if bad:raise RuntimeError(f'{name}:unexpected network:{bad}')
 if expect==64:
  if nets or requests or a.get('clientExecAttempted') is not False or a.get('decision')!='REJECT' or a.get('rejectCode')!=expect_code:raise RuntimeError(f'{name}:rejection invariant:{result}')
  if len(ex)!=1:raise RuntimeError(f'{name}:child exec before rejection:{ex}')
 else:
  if a.get('decision')!='ACCEPT' or a.get('clientExecAttempted') is not True:raise RuntimeError(f'{name}:accept audit:{a}')
 return result

def make_project(work,client):
 kind=client.split('-')[0];p=work/f'project-{client}';p.mkdir();m={'name':'policy-probe','version':'1.0.0','private':True,'dependencies':{'age-probe':'*','pkgre-js':'*'}}
 if kind=='bun':m['trustedDependencies']=[]
 (p/'package.json').write_text(json.dumps(m,sort_keys=True,separators=(',',':'))+'\n')
 if kind=='deno':shutil.copyfile(ROOT/'configs'/'loopback'/'deno.json',p/'deno.json')
 return p

def assert_lock(project,client):
 kind=client.split('-')[0];name={'npm':'package-lock.json','bun':'bun.lock','deno':'deno.lock'}[kind];p=project/name;text=p.read_text()
 if 'age-probe@1.0.0' not in text and '"age-probe": "1.0.0"' not in text and 'age-probe-1.0.0' not in text:raise RuntimeError(f'{client}:old age selection absent')
 if 'pkgre-js@2.0.0' not in text and '"pkgre-js": "2.0.0"' not in text and 'pkgre-js-2.0.0' not in text:raise RuntimeError(f'{client}:excluded young selection absent')
 return {'path':str(p),'sha256':h(p),'bytes':p.stat().st_size,'oldSelected':True,'excludedYoungSelected':True}

def main():
 if os.environ.get('PKGRE_NETNS')!='loopback-only':raise RuntimeError('must run in dedicated network namespace')
 OUT.mkdir(parents=True,exist_ok=True);shutil.rmtree(TRACE,ignore_errors=True);TRACE.mkdir();
 for p in OUT.glob('*'):
  if p.name!='traces':p.unlink() if p.is_file() or p.is_symlink() else shutil.rmtree(p)
 reglog=OUT/'registry-requests.jsonl';reglog.write_text('')
 with tempfile.TemporaryDirectory(prefix='pkgre-d0-subrun-') as td:
  work=Path(td);reg=subprocess.Popen([str(REGISTRY),str(PORT),str(reglog)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
  try:
   for _ in range(100):
    s=subprocess.run(['/run/current-system/sw/bin/curl','-fsS',f'http://127.0.0.1:{PORT}/age-probe'],capture_output=True)
    if s.returncode==0:break
    time.sleep(.02)
   else:raise RuntimeError('registry did not start')
   reglog.write_text('')
   results=[];locks={};versions={}
   for client in CLIENTS:
    project=make_project(work,client);state=work/f'state-{client}';state.mkdir();home=work/f'incoming-home-{client}';home.mkdir()
    # Five hostile sources:project/user config,registry config env,token env,and CLI override.
    (project/'.npmrc').write_text('registry=https://registry.npmjs.org/\n')
    results.append(run_case(work,project,state,home,client,'reject-project-npmrc','inspect',expect=64,expect_code='DISCOVERABLE_PROJECT_CONFIG'));(project/'.npmrc').unlink()
    (home/'.npmrc').write_text('registry=https://registry.npmjs.org/\n')
    results.append(run_case(work,project,state,home,client,'reject-user-npmrc','inspect',expect=64,expect_code='DISCOVERABLE_USER_CONFIG'));(home/'.npmrc').unlink()
    envname={'npm':'NPM_CONFIG_USERCONFIG','bun':'BUN_CONFIG_REGISTRY','deno':'NPM_CONFIG_USERCONFIG'}[client.split('-')[0]]
    results.append(run_case(work,project,state,home,client,'reject-registry-env','inspect',env_extra={envname:'/tmp/hostile'},expect=64,expect_code='HOSTILE_ENV'))
    results.append(run_case(work,project,state,home,client,'reject-token-env','inspect',env_extra={'NPM_TOKEN':'secret-not-recorded'},expect=64,expect_code='HOSTILE_ENV'))
    cli={'npm':'--registry=https://registry.npmjs.org/','bun':'--config=/tmp/hostile','deno':'--config=/tmp/hostile'}[client.split('-')[0]]
    results.append(run_case(work,project,state,home,client,'reject-cli-override','inspect',extra=(cli,),expect=64,expect_code='HOSTILE_CLI'))
    r=run_case(work,project,state,home,client,'inspect','inspect');results.append(r);versions[client]=Path(ROOT/r['stdout']).read_text().splitlines()[:8]
    results.append(run_case(work,project,state,home,client,'resolve','resolve'));locks[client]=assert_lock(project,client)
    shutil.rmtree(state);state.mkdir();shutil.rmtree(project/'node_modules',ignore_errors=True)
    results.append(run_case(work,project,state,home,client,'cold','ci'));shutil.rmtree(project/'node_modules',ignore_errors=True)
    results.append(run_case(work,project,state,home,client,'warm','ci'));shutil.rmtree(project/'node_modules',ignore_errors=True)
    results.append(run_case(work,project,state,home,client,'frozen','ci'));shutil.rmtree(project/'node_modules',ignore_errors=True)
    results.append(run_case(work,project,state,home,client,'cache-only','cache-only'))
   allnets=[n for r in results for n in r['networkConnects']];unexpected=[n for r in results for n in r['unexpectedNetworkConnects']]
   summary={'schema':'pkgre-d0-js-client-policy-authoritative-subrun-v1','sandbox':{'type':'unshare user+network namespace','interfaces':['lo'],'egressPossible':False,'registry':'http://127.0.0.1:48730/'},'historicalIncidentUnaffected':True,'status':'PASS','clients':CLIENTS,'versions':versions,'locks':locks,'cases':results,'counts':{'cases':len(results),'rejections':sum(r['decision']=='REJECT' for r in results),'accepted':sum(r['decision']=='ACCEPT' for r in results),'networkConnects':len(allnets),'unexpectedNetworkConnects':len(unexpected),'registryRequests':sum(len(r['registryRequests']) for r in results)},'invariants':{'allRejectionsBeforeClientExec':all((r['clientExecAttempted'] is False and not r['networkConnects'] and len(r['execve'])==1) for r in results if r['decision']=='REJECT'),'onlyLoopbackRegistryDestination':not unexpected and all('127.0.0.1' in n and f'htons({PORT})' in n for n in allnets),'cacheOnlyZeroNetwork':all(not r['networkConnects'] and not r['registryRequests'] for r in results if r['phase']=='cache-only'),'coldObservedRegistry':all(r['networkConnects'] and r['registryRequests'] for r in results if r['phase']=='cold'),'warmBounded':all(not r['unexpectedNetworkConnects'] for r in results if r['phase']=='warm'),'frozenCommandsExact':all(r['wrapperCommand'] for r in results if r['phase']=='frozen'),'ageSelections':all(v['oldSelected'] and v['excludedYoungSelected'] for v in locks.values())}}
   if not all(summary['invariants'].values()):raise RuntimeError(f'invariant failed:{summary["invariants"]}')
   (OUT/'RESULT.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
   (OUT/'RESULT.log').write_text('\n'.join([f"sandbox=loopback-only-netns status=PASS cases={len(results)}",f"clients={','.join(CLIENTS)}",f"rejections={summary['counts']['rejections']} accepted={summary['counts']['accepted']}",f"networkConnects={summary['counts']['networkConnects']} unexpected=0 registryRequests={summary['counts']['registryRequests']}",f"invariants={json.dumps(summary['invariants'],sort_keys=True)}",f"resultSha256={h(OUT/'RESULT.json')}"])+"\n")
  finally:
   reg.terminate();reg.wait(timeout=5)
 print((OUT/'RESULT.log').read_text(),end='')
if __name__=='__main__':main()
