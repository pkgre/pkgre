#!/usr/bin/env python3
"""Read-only D0 Git/storage/path/source inventory.

Repository commands run with ambient Git path/config/object/namespace overrides removed and
GIT_OPTIONAL_LOCKS=0. Network probes are read-only. Filesystem writes are confined to --output.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, pwd, grp, re, shutil, socket, ssl, stat, subprocess, sys, tempfile, unicodedata, urllib.parse

SCHEMA = "pkgre-d0-git-storage-inventory-v1"
REPOS = [
    {"name":"pkgre","path":"/home/dev0/repos/pkgre","expected_branch":"main","expected_head":"1d44dfeaeafef2b1a5341c13bf73647dcbc925ec","reviewed_basis":"066293df21743cbf41fb571a38f2bb94059e7274","runtime_origin_candidate":"https://github.com/pkgre/pkgre.git","runtime_ref":None},
    {"name":"pkgre-rust","path":"/home/dev0/repos/pkgre-rust","expected_branch":"main","expected_head":"f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b","reviewed_basis":"f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b","runtime_origin_candidate":"https://github.com/pkgre/rust.git","runtime_ref":"refs/heads/main"},
    {"name":"pkgre-js","path":"/home/dev0/repos/pkgre-js","expected_branch":"main","expected_head":"f43bd58bd3d4e36f8b3f4df3c002735c977acd17","reviewed_basis":"f43bd58bd3d4e36f8b3f4df3c002735c977acd17","runtime_origin_candidate":"https://github.com/pkgre/js.git","runtime_ref":"refs/heads/main"},
    {"name":"infra","path":"/home/dev0/repos/infra","expected_branch":"master","expected_head":"5f68539bd99c6952b6d73fe2596c27ad4a319f57","reviewed_basis":"5f68539bd99c6952b6d73fe2596c27ad4a319f57","runtime_origin_candidate":None,"runtime_ref":None},
]
DANGEROUS_GIT_ENV = ["GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_OBJECT_DIRECTORY","GIT_ALTERNATE_OBJECT_DIRECTORIES","GIT_NAMESPACE","GIT_INDEX_FILE","GIT_CONFIG","GIT_CONFIG_GLOBAL","GIT_CONFIG_SYSTEM","GIT_CONFIG_NOSYSTEM","GIT_CONFIG_COUNT"]
PATH_GRAMMAR = {
    "version":"source-path-grammar-proposal-v1",
    "separator":"single raw byte 0x2f between components;not part of component",
    "whole_path":"nonempty;relative;no leading/trailing/repeated separator;raw length<=4095",
    "component":"nonempty;raw length<=255;not '.'/'..';casefold != '.git';no 0x5c backslash;valid UTF-8;NFC encoded form only;no Unicode Cc/Cf/Cs/Co/Cn category;no U+007f",
    "collision_keys":"reject distinct raw paths sharing NFC,NFD,or Unicode default casefold(NFC(path).casefold()) key",
    "sort":"ascending unsigned raw path bytes",
    "materialization":"descriptor-relative,component-at-a-time,no symlink traversal;only approved directory/regular modes",
}

def now(): return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z")
def sha(b: bytes): return hashlib.sha256(b).hexdigest()
def jwrite(path: pathlib.Path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2)+"\n", encoding="utf-8")
def clean_env():
    e=os.environ.copy()
    for k in list(e):
        if k in DANGEROUS_GIT_ENV or k.startswith("GIT_CONFIG_KEY_") or k.startswith("GIT_CONFIG_VALUE_"): e.pop(k,None)
    e.update({"GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null","GIT_ATTR_NOSYSTEM":"1","LC_ALL":"C.UTF-8"})
    return e
ENV=clean_env()
def run(argv, cwd=None, timeout=300, input_bytes=None, check=False):
    p=subprocess.run(argv,cwd=cwd,env=ENV,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    d={"argv":argv,"cwd":cwd,"exit":p.returncode,"stdout":p.stdout.decode("utf-8","backslashreplace"),"stderr":p.stderr.decode("utf-8","backslashreplace")}
    if check and p.returncode: raise RuntimeError(json.dumps(d,indent=2))
    return d
def gout(repo,*args,check=True,raw=False):
    p=subprocess.run(["git","-C",repo,*args],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600)
    if check and p.returncode: raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.decode(errors='backslashreplace')}")
    return p.stdout if raw else p.stdout.decode("utf-8","surrogateescape")
def stat_obj(path, follow=False):
    p=pathlib.Path(path); s=p.stat() if follow else p.lstat(); mode=stat.S_IMODE(s.st_mode)
    typ="directory" if stat.S_ISDIR(s.st_mode) else "regular" if stat.S_ISREG(s.st_mode) else "symlink" if stat.S_ISLNK(s.st_mode) else "fifo" if stat.S_ISFIFO(s.st_mode) else "socket" if stat.S_ISSOCK(s.st_mode) else "block" if stat.S_ISBLK(s.st_mode) else "char" if stat.S_ISCHR(s.st_mode) else "other"
    try: un=pwd.getpwuid(s.st_uid).pw_name
    except KeyError: un=None
    try: gn=grp.getgrgid(s.st_gid).gr_name
    except KeyError: gn=None
    return {"path":str(p),"type":typ,"mode":f"{mode:04o}","uid":s.st_uid,"user":un,"gid":s.st_gid,"group":gn,"size":s.st_size,"device":s.st_dev,"inode":s.st_ino,"symlink_target":os.readlink(p) if typ=="symlink" else None}
def acl_obj(path):
    r=run(["getfacl","-cp",str(path)])
    x=run(["getfattr","-d","-m-","--absolute-names",str(path)])
    return {"getfacl_exit":r["exit"],"acl":r["stdout"],"getfacl_stderr":r["stderr"],"getfattr_exit":x["exit"],"xattrs":x["stdout"],"getfattr_stderr":x["stderr"]}
def parse_nul_records(data: bytes, fields: int):
    parts=data.split(b"\0");
    if parts and parts[-1]==b"": parts.pop()
    if len(parts)%fields: raise ValueError(f"bad NUL record field count {len(parts)}/{fields}")
    return [parts[i:i+fields] for i in range(0,len(parts),fields)]
def git_tree(repo, commit):
    fmt="%(objectmode)%x00%(objecttype)%x00%(objectname)%x00%(objectsize)%x00%(path)"
    data=gout(repo,"ls-tree","-r","-t","-z",f"--format={fmt}",commit,raw=True)
    entries=[]; h=hashlib.sha256(); logical=0; unique={}; mode_counts={}; type_counts={}; paths=[]
    for mb,tb,oidb,sizeb,pb in parse_nul_records(data,5):
        mode=mb.decode(); typ=tb.decode(); oid=oidb.decode(); size=0 if sizeb in {b"",b"-"} else int(sizeb);
        e={"path_b64":__import__('base64').b64encode(pb).decode(),"path_display":pb.decode("utf-8","backslashreplace"),"path_hex":pb.hex(),"mode":mode,"type":typ,"oid":oid,"object_size":size}
        entries.append(e); paths.append(pb); mode_counts[mode]=mode_counts.get(mode,0)+1; type_counts[typ]=type_counts.get(typ,0)+1
        body=b""
        if typ=="blob":
            body=gout(repo,"cat-file","blob",oid,raw=True); logical+=len(body); unique.setdefault(oid,len(body))
            if len(body)!=size: raise ValueError("cat-file size mismatch")
        h.update(mode.encode()+b"\0"+typ.encode()+b"\0"+str(len(pb)).encode()+b"\0"+pb+b"\0"+str(len(body)).encode()+b"\0"+body+b"\0")
    file_paths=[p for p,e in zip(paths,entries) if e["type"]!="tree"]
    return entries,{"entry_count":len(entries),"type_counts":type_counts,"mode_counts":mode_counts,"logical_blob_bytes_by_path":logical,"unique_blob_count":len(unique),"unique_blob_bytes":sum(unique.values()),"canonical_inventory_schema":"mode\\0type\\0raw-path-length\\0raw-path\\0blob-length\\0blob-bytes\\0;tree blob-length=0;entries=git ls-tree -r -t order","canonical_inventory_sha256":h.hexdigest()},path_analysis(file_paths)
def path_analysis(paths):
    issues=[]; maxp=(b"",0); maxc=(b"",0); maxdepth=0; keymaps={"nfc":{},"nfd":{},"casefold":{}}
    for p in paths:
        if len(p)>maxp[1]: maxp=(p,len(p))
        comps=p.split(b"/"); maxdepth=max(maxdepth,len(comps))
        local=[]
        if not p or p.startswith(b"/") or p.endswith(b"/") or b"//" in p or len(p)>4095: local.append("whole-path-shape-or-length")
        try: text=p.decode("utf-8")
        except UnicodeDecodeError: text=None; local.append("invalid-utf8")
        for c in comps:
            if len(c)>maxc[1]: maxc=(c,len(c))
            if not c or c in (b".",b"..") or len(c)>255: local.append("component-shape-or-length")
            if b"\\" in c: local.append("backslash")
            try: ct=c.decode("utf-8")
            except UnicodeDecodeError: continue
            if ct.casefold()==".git": local.append("dot-git-component")
            if unicodedata.normalize("NFC",ct)!=ct: local.append("non-nfc")
            if any(ord(ch)==0x7f or unicodedata.category(ch) in {"Cc","Cf","Cs","Co","Cn"} for ch in ct): local.append("disallowed-unicode-category")
        if text is not None:
            keys={"nfc":unicodedata.normalize("NFC",text),"nfd":unicodedata.normalize("NFD",text),"casefold":unicodedata.normalize("NFC",text).casefold()}
            for kind,key in keys.items(): keymaps[kind].setdefault(key,[]).append(p)
        if local: issues.append({"path_hex":p.hex(),"path_display":p.decode("utf-8","backslashreplace"),"reasons":sorted(set(local))})
    collisions={}
    for kind,m in keymaps.items():
        collisions[kind]=[{"paths_hex":[p.hex() for p in ps],"paths_display":[p.decode("utf-8","backslashreplace") for p in ps]} for ps in m.values() if len(set(ps))>1]
    return {"grammar":PATH_GRAMMAR,"path_count":len(paths),"violations":issues,"collision_sets":collisions,"max_path":{"bytes":maxp[1],"display":maxp[0].decode("utf-8","backslashreplace"),"hex":maxp[0].hex()},"max_component":{"bytes":maxc[1],"display":maxc[0].decode("utf-8","backslashreplace"),"hex":maxc[0].hex()},"max_depth":maxdepth}
def batch_objects(repo, selector):
    if selector=="all-local": argv=["git","-C",repo,"cat-file","--batch-all-objects","--batch-check=%(objectname) %(objecttype) %(objectsize) %(objectsize:disk)"]
    else:
        rev=gout(repo,"rev-list","--objects","--all",raw=True); oids=b"\n".join(line.split(b" ",1)[0] for line in rev.splitlines())+b"\n"
        p=run(["git","-C",repo,"cat-file","--batch-check=%(objectname) %(objecttype) %(objectsize) %(objectsize:disk)"],input_bytes=oids,check=True); return summarize_objects(p["stdout"])
    p=run(argv,check=True); return summarize_objects(p["stdout"])
def summarize_objects(text):
    out={"count":0,"decompressed_bytes":0,"object_disk_bytes_sum":0,"by_type":{}}
    for line in text.splitlines():
        a=line.split();
        if len(a)!=4: continue
        _,typ,size,disk=a; size=int(size); disk=int(disk); out["count"]+=1; out["decompressed_bytes"]+=size; out["object_disk_bytes_sum"]+=disk
        x=out["by_type"].setdefault(typ,{"count":0,"decompressed_bytes":0,"object_disk_bytes_sum":0}); x["count"]+=1;x["decompressed_bytes"]+=size;x["object_disk_bytes_sum"]+=disk
    return out
def object_files(gitdir):
    root=pathlib.Path(gitdir)/"objects"; by={}; total=0
    if root.exists():
        for dp,dn,fn in os.walk(root):
            for n in fn:
                p=pathlib.Path(dp)/n; s=p.lstat(); rel=str(p.relative_to(root)); cat="pack" if rel.startswith("pack/") and p.suffix==".pack" else "index" if rel.startswith("pack/") and p.suffix==".idx" else "bitmap" if p.suffix==".bitmap" else "promisor" if p.suffix==".promisor" else "rev" if p.suffix==".rev" else "loose" if re.match(r"^[0-9a-f]{2}/[0-9a-f]{38}$",rel) else "other"
                x=by.setdefault(cat,{"files":0,"bytes":0});x["files"]+=1;x["bytes"]+=s.st_size;total+=s.st_size
    return {"total_file_bytes":total,"by_kind":by}
def fs_walk(root):
    counts={}; specials=[]; symlinks=[]; total=0; n=0
    for dp,dn,fn in os.walk(root,topdown=True,followlinks=False):
        names=["."]+dn+fn
        for name in names:
            p=pathlib.Path(dp) if name=="." else pathlib.Path(dp)/name
            try:s=p.lstat()
            except FileNotFoundError:continue
            typ="directory" if stat.S_ISDIR(s.st_mode) else "regular" if stat.S_ISREG(s.st_mode) else "symlink" if stat.S_ISLNK(s.st_mode) else "fifo" if stat.S_ISFIFO(s.st_mode) else "socket" if stat.S_ISSOCK(s.st_mode) else "block" if stat.S_ISBLK(s.st_mode) else "char" if stat.S_ISCHR(s.st_mode) else "other"
            key=f"{typ}|{stat.S_IMODE(s.st_mode):04o}|{s.st_uid}|{s.st_gid}";x=counts.setdefault(key,{"type":typ,"mode":f"{stat.S_IMODE(s.st_mode):04o}","uid":s.st_uid,"gid":s.st_gid,"count":0,"bytes":0});x["count"]+=1;x["bytes"]+=s.st_size;n+=1;total+=s.st_size
            rel=str(p.relative_to(root)) if p!=pathlib.Path(root) else "."
            if typ=="symlink": symlinks.append({"path":rel,"target":os.readlink(p)})
            elif typ not in {"directory","regular"}: specials.append({"path":rel,"type":typ,"mode":f"{stat.S_IMODE(s.st_mode):04o}"})
    return {"entry_count":n,"apparent_bytes_sum":total,"mode_owner_type_counts":sorted(counts.values(),key=lambda x:(x["type"],x["mode"],x["uid"],x["gid"])),"symlinks":symlinks,"specials":specials}
def refs(repo):
    fmt="%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)%00%(symref)%00%(upstream)%00%(upstream:track)"
    data=gout(repo,"for-each-ref",f"--format={fmt}",raw=True)
    rows=[]
    for line in data.splitlines():
        r=line.split(b"\0")
        if len(r)!=7: raise ValueError("bad for-each-ref record")
        rows.append(dict(zip(["ref","oid","type","peeled_oid","symref","upstream","upstream_track"],[x.decode("utf-8","backslashreplace") for x in r])))
    head=gout(repo,"symbolic-ref","-q","HEAD",check=False).strip(); return {"HEAD_symbolic":head or None,"rows":rows,"namespaces":[x for x in rows if x["ref"].startswith("refs/namespaces/")],"replace":[x for x in rows if x["ref"].startswith("refs/replace/")]}
def worktrees(repo):
    data=gout(repo,"worktree","list","--porcelain","-z",raw=True); blocks=[]; cur={}
    for item in data.split(b"\0"):
        if not item:
            if cur: blocks.append(cur);cur={}
            continue
        s=item.decode("utf-8","backslashreplace"); k,_,v=s.partition(" "); cur[k]=v if _ else True
    if cur:blocks.append(cur)
    return blocks
def repo_inventory(spec):
    repo=spec["path"]; head=gout(repo,"rev-parse","HEAD").strip(); gitdir=gout(repo,"rev-parse","--path-format=absolute","--git-dir").strip(); common=gout(repo,"rev-parse","--path-format=absolute","--git-common-dir").strip(); branch=gout(repo,"symbolic-ref","-q","--short","HEAD",check=False).strip() or None
    tree,tree_summary,paths=git_tree(repo,head)
    local_cfg=[]
    cfg=gout(repo,"config","--local","--null","--show-origin","--list",raw=True)
    parts=cfg.split(b"\0")
    if parts and parts[-1]==b"": parts.pop()
    if len(parts)%2: raise ValueError("bad git config --show-origin -z record count")
    for i in range(0,len(parts),2):
        origin=parts[i]; kv=parts[i+1]; key,sep,val=kv.partition(b"\n")
        ks=key.decode("utf-8","backslashreplace"); vs=val.decode("utf-8","backslashreplace")
        sensitive=bool(re.search(r"(password|token|secret|credential|extraheader)",ks,re.I)); local_cfg.append({"origin":origin.decode(errors="backslashreplace"),"key":ks,"value":"<redacted>" if sensitive else vs,"value_sha256":sha(val) if sensitive else None})
    fsck=[run(["git","-C",repo,"fsck","--full","--strict"],timeout=600),run(["git","-C",repo,"fsck","--full","--strict","--no-dangling",head],timeout=600),run(["git","-C",repo,"rev-list","--objects","--all","--missing=print"],timeout=600)]
    alternates=pathlib.Path(common)/"objects/info/alternates"; grafts=pathlib.Path(common)/"info/grafts"; shallow=pathlib.Path(common)/"shallow"
    attrs=[e for e in tree if e["path_display"].endswith(".gitattributes") or e["path_display"] in {".gitmodules",".lfsconfig"}]
    hooks=[]
    hp=pathlib.Path(common)/"hooks"
    if hp.exists():
        for p in sorted(hp.iterdir()): hooks.append({**stat_obj(p),"active":p.is_file() and not p.name.endswith(".sample")})
    pack=run(["git","-C",repo,"count-objects","-vH"],check=True)
    parents=[]
    for p in [pathlib.Path(repo).parent,pathlib.Path(repo),pathlib.Path(gitdir),pathlib.Path(common)/"objects",pathlib.Path(common)/"refs"]:
        if p.exists(): parents.append({"stat":stat_obj(p),"access":acl_obj(p)})
    wt=worktrees(repo)
    result={**spec,"observed":{"head":head,"branch":branch,"tree":gout(repo,"rev-parse",f"{head}^{{tree}}").strip(),"upstream":gout(repo,"rev-parse","@{upstream}",check=False).strip() or None,"upstream_name":gout(repo,"rev-parse","--abbrev-ref","--symbolic-full-name","@{upstream}",check=False).strip() or None,"ahead_behind":gout(repo,"rev-list","--left-right","--count","HEAD...@{upstream}",check=False).strip() or None,"status_porcelain_v2":gout(repo,"status","--porcelain=v2","--branch","--untracked-files=all")},"git":{"version":gout(repo,"--version").strip(),"git_dir":gitdir,"common_dir":common,"bare":gout(repo,"rev-parse","--is-bare-repository").strip()=="true","inside_worktree":gout(repo,"rev-parse","--is-inside-work-tree").strip()=="true","shallow":gout(repo,"rev-parse","--is-shallow-repository").strip()=="true","object_format":{"storage":gout(repo,"rev-parse","--show-object-format=storage").strip(),"input":gout(repo,"rev-parse","--show-object-format=input").strip(),"output":gout(repo,"rev-parse","--show-object-format=output").strip(),"hash_hex_length":len(head)},"local_config":local_cfg,"refs":refs(repo),"worktrees":wt,"special_state":{"alternates":{"path":str(alternates),"exists":alternates.exists(),"content":alternates.read_text(errors="backslashreplace") if alternates.exists() else None},"grafts":{"path":str(grafts),"exists":grafts.exists(),"content":grafts.read_text(errors="backslashreplace") if grafts.exists() else None},"shallow_file":{"path":str(shallow),"exists":shallow.exists()},"promisor_files":sorted(str(p) for p in (pathlib.Path(common)/"objects/pack").glob("*.promisor")),"replace_ref_count":len(refs(repo)["replace"]),"namespace_ref_count":len(refs(repo)["namespaces"]),"tracked_control_files":attrs,"gitlinks":[e for e in tree if e["mode"]=="160000" or e["type"]=="commit"],"hooks":hooks}},"tree":{"summary":tree_summary,"paths":paths,"entries":tree},"objects":{"reachable_from_refs":batch_objects(repo,"reachable"),"all_local":batch_objects(repo,"all-local"),"storage_files":object_files(common),"count_objects_vH":pack["stdout"],"count_objects_stderr":pack["stderr"]},"checks":{"commands":fsck,"pass":all(x["exit"]==0 for x in fsck) and not any(line.startswith("?") for line in fsck[2]["stdout"].splitlines())},"filesystem":{"identity_paths":parents,"walk":fs_walk(repo)}}
    cfgmap={x["key"]:x["value"] for x in local_cfg}
    result["classification"]={"expected_head_match":head==spec["expected_head"],"expected_branch_match":branch==spec["expected_branch"],"reviewed_basis_is_ancestor":run(["git","-C",repo,"merge-base","--is-ancestor",spec["reviewed_basis"],head])["exit"]==0,"sha1_40":result["git"]["object_format"]["storage"]=="sha1" and len(head)==40,"clean":not any(line and not line.startswith("#") for line in result["observed"]["status_porcelain_v2"].splitlines()),"complete_self_contained":not result["git"]["shallow"] and not alternates.exists() and not result["git"]["special_state"]["promisor_files"] and not cfgmap.get("extensions.partialclone") and not any(k.endswith(".promisor") and v=="true" for k,v in cfgmap.items()),"no_replace_grafts_namespaces":not result["git"]["special_state"]["replace_ref_count"] and not result["git"]["special_state"]["namespace_ref_count"] and not grafts.exists(),"no_gitlinks_lfs_filters":not result["git"]["special_state"]["gitlinks"] and not any(e["path_display"].endswith(".lfsconfig") or e["path_display"].endswith(".gitattributes") for e in attrs) and not any(k.startswith("filter.") for k in cfgmap),"path_grammar_pass":not paths["violations"] and not any(paths["collision_sets"].values()),"strict_fsck_connectivity_pass":result["checks"]["pass"],"runtime_exact_refspec_configured":cfgmap.get("remote.origin.fetch") in {"+refs/heads/main:refs/pkgre/remotes/main","+refs/heads/master:refs/pkgre/remotes/master"},"runtime_safe_transport_configured":bool(cfgmap.get("http.followredirects") in {"false","initial"}) and cfgmap.get("http.sslverify","true")!="false","production_mirror_layout":result["git"]["bare"] and len(wt)==0}
    return result

def mount_inventory(path):
    fj=run(["findmnt","--json","--output","TARGET,SOURCE,FSTYPE,OPTIONS,FSROOT,MAJ:MIN","--target",str(path)],check=True)
    st=os.statvfs(path); return {"findmnt":json.loads(fj["stdout"]),"statvfs":{"block_size":st.f_bsize,"fragment_size":st.f_frsize,"blocks":st.f_blocks,"blocks_free":st.f_bfree,"blocks_available":st.f_bavail,"files":st.f_files,"files_free":st.f_ffree,"name_max":st.f_namemax},"path_max":os.pathconf(path,"PC_PATH_MAX"),"name_max":os.pathconf(path,"PC_NAME_MAX")}
def filesystem_probe(out):
    root=out/".filesystem-probe"; root.mkdir(mode=0o700,exist_ok=False)
    try:
        case_a=root/"D0Case";case_b=root/"d0case";case_a.write_bytes(b"A");case_b.write_bytes(b"B")
        nfc="é";nfd=unicodedata.normalize("NFD",nfc);(root/nfc).write_bytes(b"NFC");(root/nfd).write_bytes(b"NFD")
        bad_b=os.fsencode(root)+b"/invalid-utf8-\xff";fd=os.open(bad_b,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b"x");os.close(fd)
        before=sorted(os.listdir(os.fsencode(root))); tmp=root/"rename.tmp";dst=root/"rename.final";tmp.write_bytes(b"atomic-rename-probe");f=tmp.open("rb");os.fsync(f.fileno());f.close();os.rename(tmp,dst);dfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
        return {"mount":mount_inventory(root),"case":{"distinct":case_a.read_bytes()!=case_b.read_bytes() and case_a.stat().st_ino!=case_b.stat().st_ino,"names":[case_a.name,case_b.name]},"unicode":{"nfc_nfd_distinct":(root/nfc).stat().st_ino!=(root/nfd).stat().st_ino,"nfc_hex":os.fsencode(nfc).hex(),"nfd_hex":os.fsencode(nfd).hex(),"roundtrip_names_hex":[x.hex() for x in before]},"invalid_utf8_name_roundtrip":os.path.basename(bad_b) in before,"rename_same_directory_fsync":{"final_bytes_sha256":sha(dst.read_bytes()),"tmp_absent":not tmp.exists(),"final_present":dst.exists()},"probe_path":str(root),"writes_confined_to_output":True}
    finally: shutil.rmtree(root)
def tls_probe(host,port=443):
    ctx=ssl.create_default_context();
    with socket.create_connection((host,port),timeout=15) as raw:
        with ctx.wrap_socket(raw,server_hostname=host) as s:
            der=s.getpeercert(binary_form=True); cert=s.getpeercert(); cipher=s.cipher(); version=s.version(); peer=s.getpeername()
    return {"host":host,"port":port,"verified_default_CA_and_hostname":True,"tls_version":version,"cipher":cipher,"peer_ip":peer[0],"leaf_der_sha256":sha(der),"leaf_subject":cert.get("subject"),"leaf_issuer":cert.get("issuer"),"leaf_not_before":cert.get("notBefore"),"leaf_not_after":cert.get("notAfter"),"subject_alt_name":cert.get("subjectAltName")}
def ssh_config(host):
    cfg=run(["ssh","-G",host]); allow={"hostname","user","port","proxycommand","proxyjump","identitiesonly","stricthostkeychecking","userknownhostsfile","globalknownhostsfile","hostkeyalgorithms"}; parsed={}
    for line in cfg["stdout"].splitlines():
        k,_,v=line.partition(" ");
        if k in allow:parsed[k]=v
    kh=run(["ssh-keygen","-F",host]); keys=[]
    for line in kh["stdout"].splitlines():
        if line.startswith("#") or not line:continue
        a=line.split();
        if len(a)>=3:
            blob=__import__('base64').b64decode(a[2]+"===");keys.append({"hosts":a[0],"algorithm":a[1],"key_sha256":"SHA256:"+__import__('base64').b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")})
    return {"effective":parsed,"known_host_keys":keys,"lookup_exit":kh["exit"]}
def network_probe(spec):
    local_origin=None
    for x in gout(spec["path"],"config","--local","--get-all","remote.origin.url",check=False).splitlines(): local_origin=x
    item={"repo":spec["name"],"local_origin_bytes_utf8":local_origin,"local_origin_hex":local_origin.encode().hex() if local_origin else None,"local_transport":urllib.parse.urlparse(local_origin).scheme if local_origin and "://" in local_origin else "ssh-scp-like" if local_origin and ":" in local_origin else None,"runtime_origin_candidate":spec["runtime_origin_candidate"],"runtime_full_ref":spec["runtime_ref"]}
    if spec["runtime_origin_candidate"] and spec["runtime_ref"]:
        origin=spec["runtime_origin_candidate"]; u=urllib.parse.urlparse(origin); endpoint=origin+"/info/refs?service=git-upload-pack"
        cmd=["git","-c","protocol.allow=never","-c","protocol.https.allow=always","-c","http.sslVerify=true","-c","http.followRedirects=false","ls-remote","--exit-code","--refs",origin,spec["runtime_ref"]]
        ls=run(cmd,timeout=120); curl=run(["curl","--silent","--show-error","--output","/dev/null","--dump-header","-","--proto","=https","--tlsv1.2","--max-redirs","0","--connect-timeout","15","--max-time","60","--write-out","\nCURL_EFFECTIVE=%{url_effective}\nCURL_REDIRECT=%{redirect_url}\nCURL_HTTP=%{http_code}\nCURL_SSL_VERIFY=%{ssl_verify_result}\nCURL_VERSION=%{http_version}\n",endpoint],timeout=90)
        row=ls["stdout"].strip().split()
        item["https_read_probe"]={"git":ls,"observed_ref_oid":row[0] if len(row)>=2 else None,"observed_ref_name":row[1] if len(row)>=2 else None,"smart_http":curl,"tls":tls_probe(u.hostname),"strict_no_redirect_pass":ls["exit"]==0 and curl["exit"]==0 and "CURL_REDIRECT=\n" in curl["stdout"] and "CURL_SSL_VERIFY=0" in curl["stdout"]}
    return item

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output",required=True);a=ap.parse_args();out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    if any(p.name != "inventory.py" for p in out.iterdir()): raise SystemExit("output directory must contain at most inventory.py")
    observed_env={}
    for k in os.environ:
        if k in DANGEROUS_GIT_ENV or k.startswith("GIT_CONFIG_KEY_") or k.startswith("GIT_CONFIG_VALUE_"):
            v=os.environ[k]; observed_env[k]={"value":"<redacted>" if k.startswith("GIT_CONFIG_VALUE_") else v,"value_sha256":sha(v.encode()) if k.startswith("GIT_CONFIG_VALUE_") else None}
    meta={"schema":SCHEMA,"started_at":now(),"argv":sys.argv,"python":sys.version,"platform":run(["uname","-a"],check=True)["stdout"].strip(),"git":run(["git","--version"],check=True)["stdout"].strip(),"ambient_git_override_environment_before_scrub":observed_env,"command_environment_policy":{"removed":DANGEROUS_GIT_ENV+["GIT_CONFIG_KEY_*","GIT_CONFIG_VALUE_*"],"set":{k:ENV[k] for k in ["GIT_OPTIONAL_LOCKS","GIT_TERMINAL_PROMPT","GIT_CONFIG_NOSYSTEM","GIT_CONFIG_GLOBAL","GIT_CONFIG_SYSTEM","GIT_ATTR_NOSYSTEM","LC_ALL"]}},"scope":"read-only source repositories;network read probes;filesystem writes only beneath output","repository_mutations":"none intended;no fetch/gc/repack/checkout/worktree/submodule/LFS command"}
    repos=[repo_inventory(x) for x in REPOS]
    fs={"schema":SCHEMA,"observed_at":now(),"repositories_mount":mount_inventory("/home/dev0/repos"),"output_mount":mount_inventory(out),"safe_behavior_probe":filesystem_probe(out)}
    net={"schema":SCHEMA,"observed_at":now(),"repositories":[network_probe(x) for x in REPOS],"ssh_trust":{"github.com":ssh_config("github.com"),"gitlab.pacna.net":ssh_config("gitlab.pacna.net")},"notes":["HTTPS Git probes use protocol.allow=never+protocol.https.allow=always,http.sslVerify=true,http.followRedirects=false and one exact full ref.","Local configured origins remain SSH and were not changed.","No network write or authenticated provider-setting API call performed."]}
    meta["finished_at"]=now();jwrite(out/"run-metadata.json",meta);jwrite(out/"repositories.json",{"schema":SCHEMA,"observed_at":meta["finished_at"],"repositories":repos});jwrite(out/"filesystem.json",fs);jwrite(out/"source-network.json",net)
if __name__=="__main__":main()
