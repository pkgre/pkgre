#!/nix/store/l9k0anq0z7zz81zcwy035jfwap9ga6rl-python3-3.13.13/bin/python3.13
"""Dependency-free pre-exec policy prototype for the pinned pkg.re JS clients."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, stat, sys, tomllib
from pathlib import Path
from urllib.parse import urlparse

SCHEMA="pkgre-js-client-policy-wrapper-v1"
FORBIDDEN_ENV_EXACT={"NPM_TOKEN","NODE_AUTH_TOKEN","YARN_NPM_AUTH_TOKEN","NPM_CONFIG_USERCONFIG","NPM_CONFIG_GLOBALCONFIG","NPM_CONFIG_CACHE","NPM_CONFIG_REGISTRY","NPM_CONFIG_MIN_RELEASE_AGE","BUN_CONFIG_REGISTRY","BUN_INSTALL","BUN_INSTALL_CACHE_DIR","DENO_DIR","DENO_AUTH_TOKENS","DENO_TLS_CA_STORE","DENO_CERT","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY","NODE_EXTRA_CA_CERTS","SSL_CERT_FILE","SSL_CERT_DIR","NODE_OPTIONS"}
FORBIDDEN_CLI_PREFIXES=("--registry","--config","--userconfig","--globalconfig","--cache","--offline","--online","--prefer-online","--prefer-offline","--ignore-scripts","--foreground-scripts","--allow-scripts","--trust","--minimum-release-age","--minimum-dependency-age","--frozen","--no-frozen","--lock","--node-modules-dir","--import-map","--env-file","--allow-import","--cert")
FORBIDDEN_SOURCE_PREFIXES=("git:","git+","github:","gitlab:","bitbucket:","file:","link:","workspace:","http:","https:","jsr:","data:","blob:")
NPM_EXPECTED={"registry":None,"audit":"false","fund":"false","save-exact":"true","ignore-scripts":"true","foreground-scripts":"false","progress":"false","offline":"false","strict-npmrc":"true","allow-directory":"none","allow-file":"none","allow-git":"none","allow-remote":"none","replace-registry-host":"always","min-release-age":"30","min-release-age-exclude[]":"pkgre-js"}

class Reject(Exception):
    def __init__(self,code,detail): super().__init__(detail);self.code=code;self.detail=detail

def sha256(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def fail(code,detail):raise Reject(code,detail)
def resolve_regular(path:Path,label:str)->Path:
    try:r=path.resolve(strict=True)
    except (FileNotFoundError,RuntimeError) as e:fail("MISSING_CONTROLLED_ARTIFACT",f"{label}:{path}:{e}")
    if not r.is_file() or path.is_symlink():fail("INVALID_CONTROLLED_ARTIFACT",f"{label}:{r}")
    if stat.S_IMODE(r.stat().st_mode)&0o222:fail("WRITABLE_CONTROLLED_ARTIFACT",f"{label}:{r}")
    return r

def parse_npmrc(path:Path)->dict[str,str]:
    out={}
    for n,line in enumerate(path.read_text().splitlines(),1):
        s=line.strip()
        if not s or s.startswith(('#',';')):continue
        if '=' not in s:fail("INVALID_NPMRC",f"{path}:{n}")
        k,v=s.split('=',1);k=k.strip();v=v.strip()
        if k in out:fail("DUPLICATE_NPMRC_KEY",f"{path}:{k}")
        out[k]=v
    return out

def validate_profile(profile_path:Path):
    profile_path=resolve_regular(profile_path,"profile")
    try:p=json.loads(profile_path.read_text())
    except Exception as e:fail("INVALID_PROFILE",str(e))
    if p.get("schema")!="pkgre-js-client-policy-profile-v1":fail("INVALID_PROFILE_SCHEMA",repr(p.get("schema")))
    registry=p.get("registry");u=urlparse(registry)
    if u.scheme not in {"https","http"} or not u.hostname or u.username or u.password or u.query or u.fragment or not registry.endswith('/'):fail("INVALID_REGISTRY",repr(registry))
    if p.get("testOnly"):
        if u.scheme!="http" or u.hostname!="127.0.0.1":fail("TEST_REGISTRY_NOT_LOOPBACK",registry)
    elif registry!="https://js.pkg.re/":fail("PRODUCTION_REGISTRY_MISMATCH",registry)
    base=profile_path.parent
    cfg={k:resolve_regular(base/v,f"config:{k}") for k,v in p.get("configs",{}).items()}
    if set(cfg)!={"npm","bunCi","bunResolve","deno","denoNpmrc"}:fail("CONFIG_SET_MISMATCH",repr(sorted(cfg)))
    npm=parse_npmrc(cfg["npm"]);expected=dict(NPM_EXPECTED);expected["registry"]=registry
    if npm!=expected:fail("NPM_POLICY_MISMATCH",repr(npm))
    for key,frozen in (("bunCi",True),("bunResolve",False)):
        try:b=tomllib.loads(cfg[key].read_text())
        except Exception as e:fail("INVALID_BUN_CONFIG",f"{key}:{e}")
        exp={"install":{"registry":registry,"minimumReleaseAge":2592000,"minimumReleaseAgeExcludes":["pkgre-js"],"ignoreScripts":True,"auto":"disable","frozenLockfile":frozen}}
        if b!=exp:fail("BUN_POLICY_MISMATCH",f"{key}:{b!r}")
    try:d=json.loads(cfg["deno"].read_text())
    except Exception as e:fail("INVALID_DENO_CONFIG",str(e))
    dexp={"minimumDependencyAge":{"age":"P30D","exclude":["npm:pkgre-js"]},"allowScripts":[],"nodeModulesDir":"manual","lock":{"path":"./deno.lock","frozen":True}}
    if d!=dexp:fail("DENO_POLICY_MISMATCH",repr(d))
    if parse_npmrc(cfg["denoNpmrc"])!={"registry":registry}:fail("DENO_NPMRC_MISMATCH",str(cfg["denoNpmrc"]))
    return p,cfg,profile_path

def ancestors(path:Path):
    p=path
    while True:
        yield p
        if p.parent==p:break
        p=p.parent

def reject_discoverable_configs(project:Path,incoming_home:Path,kind:str):
    names={".npmrc"}
    if kind=="bun":names|={"bunfig.toml",".bunfig.toml"}
    if kind=="deno":names|={"deno.jsonc","deno.workspace","deno.workspace.json","deno.workspace.jsonc"}
    for base in ancestors(project):
        for name in names:
            p=base/name
            if p.exists():fail("DISCOVERABLE_PROJECT_CONFIG",str(p))
    user_names={".npmrc"}
    if kind=="bun":user_names|={"bunfig.toml",".bunfig.toml", ".config/bunfig.toml"}
    for name in user_names:
        p=incoming_home/name
        if p.exists():fail("DISCOVERABLE_USER_CONFIG",str(p))
    for p in (Path('/etc/npmrc'),Path('/usr/local/etc/npmrc'),Path('/etc/bunfig.toml')):
        if p.exists():fail("DISCOVERABLE_GLOBAL_CONFIG",str(p))

def reject_environment(env:dict[str,str]):
    bad=[]
    for k in env:
        u=k.upper()
        if u in FORBIDDEN_ENV_EXACT or u.startswith(("NPM_CONFIG_","BUN_CONFIG_","DENO_")):bad.append(k)
    if bad:fail("HOSTILE_ENV",','.join(sorted(bad,key=str.upper)))

def reject_cli(extra:list[str]):
    if not extra:return
    for a in extra:
        l=a.lower()
        if l=="--" or l.startswith('-') or any(l==x or l.startswith(x+'=') for x in FORBIDDEN_CLI_PREFIXES):fail("HOSTILE_CLI",a)
    fail("EXTRA_CLI_FORBIDDEN",repr(extra))

def scan_manifest(project:Path,kind:str):
    p=project/'package.json'
    if not p.is_file():fail("MISSING_MANIFEST",str(p))
    try:m=json.loads(p.read_text())
    except Exception as e:fail("INVALID_MANIFEST",str(e))
    if not isinstance(m,dict):fail("INVALID_MANIFEST","root-not-object")
    scripts=m.get('scripts',{})
    if scripts not in ({},None):fail("LIFECYCLE_SCRIPTS_FORBIDDEN",repr(scripts))
    if kind=='bun' and m.get('trustedDependencies')!=[]:fail("TRUSTED_DEPENDENCIES_REQUIRED_EMPTY",repr(m.get('trustedDependencies')))
    if 'trustedDependencies' in m and m['trustedDependencies']!=[]:fail("TRUSTED_DEPENDENCIES_NONEMPTY",repr(m['trustedDependencies']))
    if any(k.startswith('npm-extension') for k in m):fail("NPM_EXTENSION_FORBIDDEN","manifest")
    for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies','overrides','resolutions'):
        vals=m.get(section,{})
        if not isinstance(vals,dict):fail("INVALID_DEPENDENCY_MAP",section)
        for name,spec in vals.items():
            if not isinstance(name,str) or not isinstance(spec,str):fail("INVALID_DEPENDENCY_SPEC",f"{section}:{name!r}:{spec!r}")
            low=spec.strip().lower()
            if low.startswith(FORBIDDEN_SOURCE_PREFIXES) or '://' in low or low.startswith('npm:'):fail("SOURCE_KIND_FORBIDDEN",f"{section}:{name}:{spec}")
    for pattern in ('.npm-extension.*','package-lock.json.*','bun.lock.*','deno.lock.*'):
        if list(project.glob(pattern)):fail("LOCK_EXTENSION_FORBIDDEN",pattern)

def scan_lock(project:Path,kind:str,registry:str,required:bool):
    names={'npm':'package-lock.json','bun':'bun.lock','deno':'deno.lock'};p=project/names[kind]
    if not p.exists():
        if required:fail("COMMITTED_LOCK_REQUIRED",str(p))
        return
    if not p.is_file() or p.is_symlink():fail("INVALID_LOCK",str(p))
    text=p.read_text(errors='strict');low=text.lower()
    for prefix in FORBIDDEN_SOURCE_PREFIXES:
        if prefix in low and not (prefix in ('http:','https:') and registry.lower() in low):fail("LOCK_SOURCE_KIND_FORBIDDEN",prefix)
    urls=re.findall(r'https?://[^\s"\]]+',text)
    for url in urls:
        clean=url.rstrip("',},")
        if not clean.startswith(registry):fail("FOREIGN_LOCK_URL",clean)
    if kind=='npm':
        try:o=json.loads(text)
        except Exception as e:fail("INVALID_LOCK",str(e))
        if o.get('lockfileVersion')!=3:fail("LOCK_SCHEMA_MISMATCH",repr(o.get('lockfileVersion')))
        for v in o.get('packages',{}).values():
            if isinstance(v,dict) and v.get('hasInstallScript'):fail("LOCK_SCRIPT_REQUIREMENT",repr(v.get('name')))
    if kind=='deno':
        try:o=json.loads(text)
        except Exception as e:fail("INVALID_LOCK",str(e))
        if o.get('version')!='5':fail("LOCK_SCHEMA_MISMATCH",repr(o.get('version')))
        for v in o.get('npm',{}).values():
            if isinstance(v,dict) and v.get('scripts'):fail("LOCK_SCRIPT_REQUIREMENT","deno npm scripts=true")

def validate_deno_project_config(project:Path,controlled:Path):
    p=project/'deno.json'
    if not p.is_file() or p.is_symlink():fail("CONTROLLED_DENO_CONFIG_REQUIRED",str(p))
    if p.read_bytes()!=controlled.read_bytes():fail("PROJECT_DENO_CONFIG_MISMATCH",str(p))

def clean_dir(path:Path):
    if path.exists():
        if path.is_symlink() or not path.is_dir():fail("INVALID_STATE_PATH",str(path))
    else:path.mkdir(parents=True,mode=0o700)

def audit(path:Path,event:dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    data=json.dumps(event,sort_keys=True,separators=(',',':'))+'\n'
    path.write_text(data)

def main():
    ap=argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument('--profile',required=True);ap.add_argument('--client-id',required=True);ap.add_argument('--project-root',required=True);ap.add_argument('--state-root',required=True);ap.add_argument('--audit-log',required=True);ap.add_argument('--mode',required=True,choices=('inspect','resolve','ci','cache-only'))
    ns,extra=ap.parse_known_args();ns.extra=extra;event={'schema':SCHEMA,'decision':'REJECT','clientExecAttempted':False,'clientId':ns.client_id,'mode':ns.mode}
    try:
        project=Path(ns.project_root).resolve(strict=True);state=Path(ns.state_root).resolve();incoming_home=Path(os.environ.get('HOME','/nonexistent')).resolve()
        if not project.is_dir() or project.is_symlink():fail("INVALID_PROJECT_ROOT",str(project))
        p,cfg,profile_path=validate_profile(Path(ns.profile))
        client=p.get('clients',{}).get(ns.client_id)
        if not client:fail("UNKNOWN_CLIENT",ns.client_id)
        kind=client.get('kind');binary=resolve_regular(Path(client.get('binary','')),"client-binary")
        reject_environment(dict(os.environ));reject_cli(ns.extra);reject_discoverable_configs(project,incoming_home,kind);scan_manifest(project,kind)
        if kind=='deno':validate_deno_project_config(project,cfg['deno'])
        scan_lock(project,kind,p['registry'],required=ns.mode in ('ci','cache-only'))
        clean_dir(state);home=state/f'home-{ns.client_id}';cache=state/f'cache-{ns.client_id}';xdg=state/f'xdg-{ns.client_id}'
        for d in (home,cache,xdg):clean_dir(d)
        if kind=='deno':
            target=home/'.npmrc'
            if target.exists():
                if not target.is_file() or target.is_symlink() or target.read_bytes()!=cfg['denoNpmrc'].read_bytes():fail("CONTROLLED_HOME_TAMPERED",str(target))
            else:
                target.write_bytes(cfg['denoNpmrc'].read_bytes());target.chmod(0o400)
        env={'HOME':str(home),'PATH':str(binary.parent),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC','NO_COLOR':'1','TERM':'dumb'}
        if kind=='npm':
            env.update({'NPM_CONFIG_USERCONFIG':str(cfg['npm']),'NPM_CONFIG_GLOBALCONFIG':'/dev/null','NPM_CONFIG_CACHE':str(cache)})
            commands={'inspect':[str(binary),'config','ls','-l'],'resolve':[str(binary),'install','--package-lock-only'],'ci':[str(binary),'ci'],'cache-only':[str(binary),'ci','--offline']}
        elif kind=='bun':
            env.update({'XDG_CONFIG_HOME':str(xdg),'BUN_INSTALL_CACHE_DIR':str(cache)})
            conf=cfg['bunResolve'] if ns.mode=='resolve' else cfg['bunCi']
            commands={'inspect':[str(binary),'--version'],'resolve':[str(binary),f'--config={conf}','install','--ignore-scripts'],'ci':[str(binary),f'--config={conf}','install','--frozen-lockfile','--ignore-scripts'],'cache-only':[str(binary),f'--config={conf}','install','--frozen-lockfile','--ignore-scripts']}
        elif kind=='deno':
            env.update({'DENO_DIR':str(cache),'DENO_NO_UPDATE_CHECK':'1'})
            commands={'inspect':[str(binary),'--version'],'resolve':[str(binary),'install','--frozen=false'],'ci':[str(binary),'ci'],'cache-only':[str(binary),'ci']}
        else:fail("INVALID_CLIENT_KIND",repr(kind))
        cmd=commands[ns.mode];event.update({'decision':'ACCEPT','clientExecAttempted':True,'kind':kind,'binary':str(binary),'binarySha256':sha256(binary),'profile':str(profile_path),'profileSha256':sha256(profile_path),'registry':p['registry'],'projectRoot':str(project),'controlledHome':str(home),'command':cmd,'sanitizedEnvKeys':sorted(env)})
        audit(Path(ns.audit_log),event);os.chdir(project);os.execve(str(binary),cmd,env)
    except Reject as e:
        event.update({'rejectCode':e.code,'detail':e.detail});audit(Path(ns.audit_log),event);print(json.dumps(event,sort_keys=True),file=sys.stderr);return 64
    except Exception as e:
        event.update({'rejectCode':'WRAPPER_INTERNAL_ERROR','detail':f'{type(e).__name__}:{e}'});audit(Path(ns.audit_log),event);print(json.dumps(event,sort_keys=True),file=sys.stderr);return 70
if __name__=='__main__':sys.exit(main())
