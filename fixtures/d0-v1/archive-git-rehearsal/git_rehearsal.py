#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, subprocess, sys, time
RUN=pathlib.Path(sys.argv[1]).resolve()
RAW=RUN/'objects'; SRC=RUN/'scratch-import'; BARE=RUN/'scratch-bare.git'; CHECKOUT=RUN/'scratch-checkout'; FETCH=RUN/'scratch-fetch.git'
for p in [SRC,BARE,CHECKOUT,FETCH]:
    if p.exists(): shutil.rmtree(p)

def run(args,cwd=None,stdout=subprocess.PIPE):
    t=time.monotonic(); p=subprocess.run(args,cwd=cwd,check=True,stdout=stdout,stderr=subprocess.PIPE); return time.monotonic()-t,p

def apparent(p):
    return sum(x.stat().st_size for x in p.rglob('*') if x.is_file() and not x.is_symlink())
def allocated(p):
    return sum(x.stat().st_blocks*512 for x in p.rglob('*') if x.is_file() and not x.is_symlink())
def cmdout(args,cwd=None): return subprocess.run(args,cwd=cwd,check=True,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.strip()
def hash_file(p):
    h=hashlib.sha256(); n=0
    with p.open('rb') as f:
        while b:=f.read(1024*1024): h.update(b); n+=len(b)
    return h.hexdigest(),n
metrics={}
metrics['git_version']=cmdout(['git','--version'])
metrics['filesystem']=cmdout(['df','-T',str(RUN)]).splitlines()[-1]
metrics['raw_unique_count']=len(list(RAW.glob('*.crate')))
metrics['raw_unique_bytes']=sum(p.stat().st_size for p in RAW.glob('*.crate'))
metrics['raw_allocated_bytes']=sum(p.stat().st_blocks*512 for p in RAW.glob('*.crate'))

SRC.mkdir(mode=0o700)
t,p=run(['cp','-a','--reflink=never',str(RAW),str(SRC/'archives')]); metrics['copy_tree_seconds']=t
shutil.copyfile(RUN/'downloads.json',SRC/'downloads.json')
t,p=run(['git','init','--initial-branch=main','.'],cwd=SRC); metrics['git_init_seconds']=t
for k,v in [('user.name','D0 archive rehearsal'),('user.email','d0-rehearsal.invalid'),('pack.threads','4'),('pack.windowMemory','256m'),('gc.auto','0')]: run(['git','config',k,v],cwd=SRC)
t,p=run(['git','add','--','archives','downloads.json'],cwd=SRC); metrics['git_add_seconds']=t
t,p=run(['git','commit','-m','Scratch archive import rehearsal'],cwd=SRC); metrics['git_commit_seconds']=t
metrics['import_seconds']=metrics['copy_tree_seconds']+metrics['git_init_seconds']+metrics['git_add_seconds']+metrics['git_commit_seconds']
metrics['commit']=cmdout(['git','rev-parse','HEAD'],cwd=SRC)
metrics['object_format']=cmdout(['git','rev-parse','--show-object-format'],cwd=SRC)
metrics['loose_count_objects']=cmdout(['git','count-objects','-v'],cwd=SRC)
metrics['loose_repo_apparent_bytes']=apparent(SRC/'.git')
metrics['loose_repo_allocated_bytes']=allocated(SRC/'.git')
metrics['source_checkout_apparent_bytes']=apparent(SRC)-metrics['loose_repo_apparent_bytes']
metrics['source_checkout_allocated_bytes']=allocated(SRC)-metrics['loose_repo_allocated_bytes']

t,p=run(['git','-c','pack.threads=4','-c','pack.windowMemory=256m','repack','-a','-d'],cwd=SRC); metrics['pack_seconds']=t
metrics['packed_count_objects']=cmdout(['git','count-objects','-v'],cwd=SRC)
metrics['packed_repo_apparent_bytes']=apparent(SRC/'.git')
metrics['packed_repo_allocated_bytes']=allocated(SRC/'.git')
metrics['pack_files']=[{'name':p.name,'bytes':p.stat().st_size} for p in sorted((SRC/'.git/objects/pack').iterdir()) if p.is_file()]
metrics['fsck_source']=cmdout(['git','fsck','--strict','--full'],cwd=SRC)

t,p=run(['git','clone','--bare','--no-local',f'file://{SRC}',str(BARE)]); metrics['bare_clone_seconds']=t
metrics['bare_repo_apparent_bytes']=apparent(BARE); metrics['bare_repo_allocated_bytes']=allocated(BARE)
metrics['bare_count_objects']=cmdout(['git','count-objects','-v'],cwd=BARE); metrics['fsck_bare']=cmdout(['git','fsck','--strict','--full'],cwd=BARE)

t,p=run(['git','clone','--no-local',f'file://{BARE}',str(CHECKOUT)]); metrics['checkout_clone_seconds']=t
metrics['checkout_repo_apparent_bytes']=apparent(CHECKOUT/'.git'); metrics['checkout_repo_allocated_bytes']=allocated(CHECKOUT/'.git')
metrics['checkout_tree_apparent_bytes']=apparent(CHECKOUT)-metrics['checkout_repo_apparent_bytes']; metrics['checkout_tree_allocated_bytes']=allocated(CHECKOUT)-metrics['checkout_repo_allocated_bytes']
metrics['checkout_count_objects']=cmdout(['git','count-objects','-v'],cwd=CHECKOUT)

# Explicit empty-bare fetch rehearsal, then materialize to a separate work tree.
t,p=run(['git','init','--bare',str(FETCH)]); metrics['fetch_init_seconds']=t
t,p=run(['git','-C',str(FETCH),'-c','pack.threads=4','fetch','--no-tags',f'file://{BARE}','+refs/heads/main:refs/heads/main']); metrics['fetch_seconds']=t
metrics['fetch_repo_apparent_bytes']=apparent(FETCH); metrics['fetch_repo_allocated_bytes']=allocated(FETCH)
metrics['fetch_count_objects']=cmdout(['git','count-objects','-v'],cwd=FETCH); metrics['fsck_fetch']=cmdout(['git','fsck','--strict','--full'],cwd=FETCH)

# Independent checkout verification: manifest and every content-addressed filename.
manifest_hash,_=hash_file(CHECKOUT/'downloads.json'); metrics['checkout_manifest_sha256']=manifest_hash
bad=[]; checked=0; total=0
for p in sorted((CHECKOUT/'archives').glob('*.crate')):
    got,n=hash_file(p); checked+=1; total+=n
    if got!=p.stem: bad.append({'path':str(p),'expected':p.stem,'actual':got})
metrics['checkout_verified_count']=checked; metrics['checkout_verified_bytes']=total; metrics['checkout_bad_hashes']=bad
# Validate route manifest coverage against checked files.
routes=json.loads((CHECKOUT/'downloads.json').read_bytes())['routes']; declared={r['sha256'] for r in routes}; actual={p.stem for p in (CHECKOUT/'archives').glob('*.crate')}
metrics['checkout_declared_hash_count']=len(declared); metrics['checkout_missing_declared_hashes']=sorted(declared-actual); metrics['checkout_extra_hashes']=sorted(actual-declared)
raw=metrics['raw_unique_bytes']
for key in ['loose_repo_apparent_bytes','loose_repo_allocated_bytes','packed_repo_apparent_bytes','packed_repo_allocated_bytes','bare_repo_apparent_bytes','bare_repo_allocated_bytes','checkout_repo_apparent_bytes','checkout_repo_allocated_bytes','checkout_tree_apparent_bytes','checkout_tree_allocated_bytes','fetch_repo_apparent_bytes','fetch_repo_allocated_bytes']:
    metrics[key.replace('_bytes','_amplification')]=metrics[key]/raw
(RUN/'git-metrics.json').write_text(json.dumps(metrics,indent=2,sort_keys=True)+'\n')
print(json.dumps(metrics,indent=2,sort_keys=True))
if bad or declared!=actual or checked!=747 or total!=raw: sys.exit(1)
