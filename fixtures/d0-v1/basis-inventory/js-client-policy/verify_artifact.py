#!/usr/bin/env python3
"""Offline, dependency-free verifier for this evidence packet; performs no network I/O."""
import hashlib,json,re,stat,sys,tomllib
from pathlib import Path
R=Path(__file__).resolve().parent
INCIDENT_HASH='9d06853e9fa692c4b6347af8ac4bb85049d76322c41330768b5782e5df888efe'
CLIENTS=['npm-minimum','npm-current','bun-minimum','bun-current','deno-minimum','deno-current']
def die(x):raise SystemExit('FAIL '+x)
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):
 try:return json.loads((R/p).read_text())
 except Exception as e:die(f'json {p}: {e}')
def regular(p):return p.is_file() and not p.is_symlink()
# Filesystem+manifest:all regular packet files except manifest itself must be covered exactly once.
if any(p.is_symlink() for p in R.rglob('*')):die('symlink present')
manifest=[]
for n,line in enumerate((R/'SHA256SUMS').read_text().splitlines(),1):
 m=re.fullmatch(r'([0-9a-f]{64})  ([^\0\r\n]+)',line)
 if not m:die(f'bad SHA256SUMS line {n}')
 digest,name=m.groups();p=R/name
 if name=='SHA256SUMS' or name.startswith('/') or '..' in Path(name).parts or not regular(p):die(f'unsafe/missing manifest entry {name}')
 if h(p)!=digest:die(f'hash mismatch {name}')
 manifest.append(name)
if len(manifest)!=len(set(manifest)) or manifest!=sorted(manifest):die('manifest duplicate/unsorted')
actual=sorted(str(p.relative_to(R)) for p in R.rglob('*') if regular(p) and p.name!='SHA256SUMS')
if manifest!=actual:die(f'manifest coverage missing={sorted(set(actual)-set(manifest))} extra={sorted(set(manifest)-set(actual))}')
# Immutable historical incident.
inc=R/'raw/incident.txt'
if h(inc)!=INCIDENT_HASH:die('incident hash')
it=inc.read_text()
for x in ('constraint=no-public-registry-contact','result=FAIL','GET https://registry.npmjs.org/probe-missing - 404','no package installation, publish, login, token, or mutation occurred'):
 if x not in it:die('incident disclosure '+x)
# Profiles+exact config policy, independently checked.
expected_clients=None
for name,registry,test in [('production','https://js.pkg.re/',False),('loopback','http://127.0.0.1:48730/',True)]:
 base=R/'configs'/name;p=load(f'configs/{name}/profile.json')
 if p.get('schema')!='pkgre-js-client-policy-profile-v1' or p.get('name')!=name or p.get('registry')!=registry or p.get('testOnly') is not test:die('profile '+name)
 if list(p.get('clients',{}))!=CLIENTS:die('clients '+name)
 shape={k:{q:v for q,v in x.items() if q not in ('binary','drv')} for k,x in p['clients'].items()}
 if expected_clients is None:expected_clients=shape
 elif shape!=expected_clients:die('profile client drift')
 npm={}
 for line in (base/'npm.npmrc').read_text().splitlines():
  k,v=line.split('=',1);npm[k]=v
 ne={'registry':registry,'audit':'false','fund':'false','save-exact':'true','ignore-scripts':'true','foreground-scripts':'false','progress':'false','offline':'false','strict-npmrc':'true','allow-directory':'none','allow-file':'none','allow-git':'none','allow-remote':'none','replace-registry-host':'always','min-release-age':'30','min-release-age-exclude[]':'pkgre-js'}
 if npm!=ne or (base/'deno.npmrc').read_text()!=f'registry={registry}\n':die('npmrc '+name)
 de={'minimumDependencyAge':{'age':'P30D','exclude':['npm:pkgre-js']},'allowScripts':[],'nodeModulesDir':'manual','lock':{'path':'./deno.lock','frozen':True}}
 if load(f'configs/{name}/deno.json')!=de:die('deno config '+name)
 for fn,frozen in [('bun-ci.toml',True),('bun-resolve.toml',False)]:
  b=tomllib.loads((base/fn).read_text());exp={'install':{'registry':registry,'minimumReleaseAge':2592000,'minimumReleaseAgeExcludes':['pkgre-js'],'ignoreScripts':True,'auto':'disable','frozenLockfile':frozen}}
  if b!=exp:die('bun config '+name+'/'+fn)
 for fn in p['configs'].values():
  q=base/fn
  if not regular(q) or stat.S_IMODE(q.stat().st_mode)&0o222:die('writable/nonregular controlled config '+str(q.relative_to(R)))
# Existing clean authoritative subrun; verify structure, per-file hashes, rejections, socket destinations, exact frozen/cache commands.
s=load('raw/subrun/RESULT.json')
if s.get('schema')!='pkgre-d0-js-client-policy-authoritative-subrun-v1' or s.get('status')!='PASS':die('subrun status')
if s.get('clients')!=CLIENTS or s.get('counts')!={'accepted':36,'cases':66,'networkConnects':36,'registryRequests':36,'rejections':30,'unexpectedNetworkConnects':0}:die('subrun counts')
if not all(s.get('invariants',{}).values()) or set(s['invariants'])!={'ageSelections','allRejectionsBeforeClientExec','cacheOnlyZeroNetwork','coldObservedRegistry','frozenCommandsExact','onlyLoopbackRegistryDestination','warmBounded'}:die('subrun invariants')
if s.get('sandbox')!={'type':'unshare user+network namespace','interfaces':['lo'],'egressPossible':False,'registry':'http://127.0.0.1:48730/'}:die('sandbox claim')
if len(s['cases'])!=66 or len({x['id'] for x in s['cases']})!=66:die('case cardinality')
for c in s['cases']:
 for key in ('trace','audit','stdout','stderr'):
  p=R/c[key]
  if not regular(p) or h(p)!=c[key+'Sha256']:die(c['id']+' '+key+' hash')
 if c['unexpectedNetworkConnects']:die(c['id']+' unexpected network')
 for x in c['networkConnects']:
  if '127.0.0.1' not in x or 'htons(48730)' not in x:die(c['id']+' nonloopback socket')
 for q in c['registryRequests']:
  if q.get('client')!='127.0.0.1' or q.get('host')!='127.0.0.1:48730' or q.get('method')!='GET':die(c['id']+' registry request')
 if c['decision']=='REJECT':
  if c['returnCode']!=64 or c['clientExecAttempted'] is not False or c['networkConnects'] or c['registryRequests'] or len(c['execve'])!=1:die(c['id']+' rejection')
 elif c['decision']=='ACCEPT':
  if c['returnCode']!=0 or c['clientExecAttempted'] is not True:die(c['id']+' acceptance')
 else:die(c['id']+' decision')
 if c['phase']=='cache-only' and (c['networkConnects'] or c['registryRequests']):die(c['id']+' cache-only network')
# Reports must disclose the incident and final split verdict.
md=(R/'REPORT.md').read_text();rep=load('REPORT.json')
for x in (INCIDENT_HASH,'GET https://registry.npmjs.org/probe-missing','client-policy packet:PASS','D0 overall:BLOCKED'):
 if x not in md:die('REPORT.md marker '+x)
if rep.get('packetStatus')!='PASS' or rep.get('d0Overall')!='BLOCKED' or rep.get('incident',{}).get('sha256')!=INCIDENT_HASH:die('REPORT.json verdict')
print(f'PASS files={len(actual)} sha256Entries={len(manifest)} cases=66 accepted=36 rejected=30 sockets=36 unexpected=0 registryRequests=36 incident={INCIDENT_HASH}')
