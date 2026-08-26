#!/usr/bin/env python3
"""Offline dependency-free verifier for the D0 live deployment/network packet;performs no network I/O."""
import hashlib,json,re,sys
from pathlib import Path
R=Path(__file__).resolve().parent
RAW={
'github-pages-provider-live.json':('76bfa2c7d0740a2b8c2abd4c5fb42aa9d382a4ed3e7efe38c63aed5cf8e95656',30590),
'infra-repository-declared.txt':('e0fa3d8b92fea4d8653cc7877654645b3856f2f50b44016c414efed5854440a7',19434),
'prior-privileged-path-metadata.txt':('3a7db70949e6018497dbc80b7f58635fd31d376281492d6be0ef5bcac46cfda1',1373),
'public-dns-tls-http-live.txt':('ed985eacd2c4b0d2d13490548ba698b7b108e3dc1ca9d48039bd1cb8f154e639',17922),
'rain-acme-declaration-live.txt':('f1f5c3cd704e9c7971703a333c8cee97819d250795ea74e77536bf77d411b353',2114),
'rain-container-declaration-live.txt':('dd7af7553eaa9c9640a6154f8b31b944a64c74cfb08dc9c42d67208eeee2957b',5126),
'rain-container-live.txt':('d4b918e1294d906eb81fa5b001b1e86d4713fcee6eaa030ea0ea5f60b86d0944',13593),
'rain-container-units-live.txt':('19a0aca955aca128efd1ced1f360de6c4532baacc0fa5bb505251969e26353f5',39631),
'rain-host-live.txt':('31354b851b07aae96756bc8426da1690d530947e0378a5935a3c546992ea02db',17906),
'ssh-host-key-continuity.txt':('0b881cc8f015244391270c5ed7f27e8e035e5eb02f6129cfb9746d86fadb2554',1677),
}
CLASS={
'collection-boundary':'observed','rain-host-generation':'observed','rain-container-generation':'observed','rain-container-addresses':'observed','deployed-source-commit':'blocked','nginx-runtime':'observed','legacy-backend-listeners':'observed','legacy-backend-firewall':'observed','external-denial-scope':'blocked','legacy-download-binary':'observed','legacy-proxy-binary':'observed','legacy-unit-hardening':'observed','legacy-unit-resource-contract':'absent','dynamic-services':'absent','dns-topology':'observed','public-tls':'observed','acme-runtime':'observed','certificate-path-current-metadata':'blocked','certificate-path-historical-metadata':'observed','rust-pages':'observed','js-pages':'observed','js-pages-https-enforcement':'absent','pages-actions-policy':'observed','catalog-tip-signatures':'observed','pages-artifact-retention':'blocked','public-legacy-routes':'observed','wrong-host-dispatch':'observed','exact-sni-authority-rejection':'absent','time-sync':'observed','acceptance-clock-policy':'blocked','host-filesystem':'observed','production-state-dataset':'blocked','production-state-ownership':'blocked','production-rename-proof':'blocked','backup-restore':'blocked','gandi-credential-metadata':'observed','gandi-credential-remediation':'blocked','rain-ssh-continuity':'observed','rain-ssh-attestation':'blocked','release-signing-authority':'blocked','lan-instances':'absent','packet-verdict':'blocked',
}
def die(msg):raise SystemExit('FAIL '+msg)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(rel):
 try:return json.loads((R/rel).read_text())
 except Exception as e:die(f'json {rel}: {e}')
def need(text,*markers):
 for marker in markers:
  if marker not in text:die('missing marker '+repr(marker))
# Filesystem+fixed raw-byte identity.
if any(p.is_symlink() for p in R.rglob('*')):die('symlink present')
actual_raw=sorted(p.name for p in (R/'raw').iterdir() if p.is_file() and not p.is_symlink())
if actual_raw!=sorted(RAW):die(f'raw set {actual_raw}')
for name,(digest,size) in RAW.items():
 p=R/'raw'/name
 if p.stat().st_size!=size or sha(p)!=digest:die('raw identity '+name)
# Complete,sorted,non-self-referential checksum coverage.
manifest=[]
for n,line in enumerate((R/'SHA256SUMS').read_text().splitlines(),1):
 m=re.fullmatch(r'([0-9a-f]{64})  ([^\0\r\n]+)',line)
 if not m:die(f'bad SHA256SUMS line {n}')
 digest,name=m.groups();path=R/name
 if name=='SHA256SUMS' or name.startswith('/') or '..' in Path(name).parts or not path.is_file() or path.is_symlink():die('unsafe/missing manifest entry '+name)
 if sha(path)!=digest:die('manifest hash '+name)
 manifest.append(name)
if manifest!=sorted(manifest) or len(manifest)!=len(set(manifest)):die('manifest unsorted/duplicate')
actual=sorted(str(p.relative_to(R)) for p in R.rglob('*') if p.is_file() and not p.is_symlink() and p.name!='SHA256SUMS')
if manifest!=actual:die(f'manifest coverage missing={sorted(set(actual)-set(manifest))} extra={sorted(set(manifest)-set(actual))}')
# Parse every JSON file.
for p in sorted(R.rglob('*.json')):
 try:json.loads(p.read_text())
 except Exception as e:die(f'json parse {p.relative_to(R)}: {e}')
rep=load('REPORT.json');val=load('validation.json');pages=load('raw/github-pages-provider-live.json')
if rep.get('schema')!='pkgre-d0-live-deployment-network-report-v1' or rep.get('packetStatus')!='PASS' or rep.get('d0Overall')!='BLOCKED' or rep.get('d1Authorized') is not False:die('report split verdict')
if rep.get('networkDuringFinalization')!='none;reports+checksums derived only from preserved raw files':die('finalization boundary')
if rep.get('operations')!={'deploymentMutation':False,'dnsMutation':False,'providerMutation':False,'repositoryModifiedByCollection':False,'secretsRead':False}:die('operation boundary')
# Every material machine-readable claim has one exact permitted classification;proposals are not relabeled observations.
claims=rep.get('claims',[])
if len(claims)!=len(CLASS) or len({x.get('id') for x in claims})!=len(CLASS):die('claim cardinality')
got={x.get('id'):x.get('classification') for x in claims}
if got!=CLASS:die(f'classification map mismatch {got}')
allowed={'observed','proposed','absent','blocked'}
if any(set(x)!={'id','classification','summary','evidence','values'} for x in claims):die('claim schema')
if any(x['classification'] not in allowed or not x['summary'] or not x['evidence'] for x in claims):die('claim fields')
counts={k:sum(v==k for v in got.values()) for k in ('observed','proposed','absent','blocked')}
if counts!={'observed':24,'proposed':0,'absent':5,'blocked':13} or rep.get('classificationCounts')!=counts:die('classification counts')
if got['production-state-dataset']!='blocked' or got['legacy-unit-resource-contract']!='absent' or got['gandi-credential-remediation']!='blocked':die('proposal/absence classification')
for x in claims:
 for ev in x['evidence']:
  base=ev.split('#',1)[0]
  if not (R/base).exists():die(f'evidence reference {x["id"]}: {base}')
# Fixed report raw inventory.
if set(rep.get('rawFiles',{}))!=set(RAW):die('report raw set')
for name,(digest,size) in RAW.items():
 if rep['rawFiles'][name]!={'bytes':size,'sha256':digest}:die('report raw row '+name)
# Critical cross-evidence values.
host=(R/'raw/rain-host-live.txt').read_text();container=(R/'raw/rain-container-live.txt').read_text();decl=(R/'raw/infra-repository-declared.txt').read_text();wire=(R/'raw/public-dns-tls-http-live.txt').read_text();units=(R/'raw/rain-container-units-live.txt').read_text();ssh=(R/'raw/ssh-host-key-continuity.txt').read_text();prior=(R/'raw/prior-privileged-path-metadata.txt').read_text()
need(host,'current_system=/nix/store/bhfadnwczhfsd6zadxhl04jqfp1spp9v-nixos-system-rain-26.11.20260818.9588f1a','nginx version: nginx/1.30.4','eeb69be6aebb5e69fdbc12c9019e648f64308b1738c153715411db607d701d51  /nix/store/nnqs127xdnxi93772sgmgfy7a890alxb-nginx.conf','kind=regular file mode=644 owner=root:root uid=0 gid=0 size=41 path=/var/lib/keys/pkgre-js-gandiv5-token','System clock synchronized: yes','NTP service: active','Root distance: 831us (max: 5s)','Offset: -198us')
need(container,'Address: 10.22.2.5','10.131.7.4','6178808','5613352')
need(decl,'commit=5f68539bd99c6952b6d73fe2596c27ad4a319f57','pkgreDownload = 9008;','pkgreProxy = 9009;','ip saddr ${hostLocalIp} tcp dport { ${toString legacyPort}, ${toString proxyPort} } accept')
need(units,'root=/nix/store/jai70s8kdn3jc71qvsn9l20zma9aam4g-nixos-system-pkgre-26.11.20260818.9588f1a','DynamicUser=true','NoNewPrivileges=true','ExecStart=/nix/store/wjrvwfxnxzwjvkvcl3j53wkbrgvbkznf-pkgre-download-serve-0.1.0/bin/pkgre-download-serve --listen 10.131.7.4:9008','ExecStart=/nix/store/1a25f3q7qvdxgcbcjs267h395xzy4016-pkgre-proxy-0.2.0/bin/pkgre-proxy --listen 10.131.7.4:9009')
need(wire,'rust.pkg.re.\t\t300\tIN\tCNAME\tpkgre.github.io.','js.pkg.re.\t\t300\tIN\tCNAME\train.pacna.org.','dl.rust.pkg.re.\t\t10800\tIN\tCNAME\train.pacna.org.','## http js_canary','status=502','HTTP/2 307','location: https://static.crates.io/crates/accessory/2.1.0/download','body_sha256=28e416a3ab45838bac2ab2d81b1088d738d7b2d2c5272a54d39366565a29bd80','Location: https://admin.keycloak.pacna.net/admin/')
need(ssh,'classification=TOFU/continuity evidence;not operator attestation','ssh_identity=uid=1000(wei)','fingerprint=SHA256:+lFmS5DwoVcWRZduvk+R0zSnHJ++C8JRL1kopXnidiI')
if ssh.count('match=true')!=10:die('SSH continuity scan count')
need(prior,'regular file 640 acme:nginx 993:60 4807 /var/lib/acme/rust.pkg.re/fullchain.pem','regular file 640 acme:nginx 993:60 227 /var/lib/acme/js.pkg.re/key.pem')
# Provider values.
if pages.get('schema')!='pkgre-d0-pages-provider-live-v1' or pages.get('collection',{}).get('mutation') is not False:die('provider collection')
rust=pages['repositories']['rust'];js=pages['repositories']['js']
if rust['repository']['default_tip']!={'reason':'valid','sha':'f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b','signature_kind':'pgp','verified':True}:die('Rust tip')
if js['repository']['default_tip']!={'reason':'unsigned','sha':'f43bd58bd3d4e36f8b3f4df3c002735c977acd17','signature_kind':'absent','verified':False}:die('JS tip')
if rust['pages']['cname']!='rust.pkg.re' or rust['pages']['https_enforced'] is not True or rust['deployments'][0]['id']!=6092749507:die('Rust Pages')
if js['pages']['cname']!='js.pkg.re' or js['pages']['https_enforced'] is not False or js['deployments'][0]['id']!=6094120375:die('JS Pages')
if rust['repository_actions_permissions']['allowed_actions']!='selected' or rust['repository_actions_permissions']['sha_pinning_required'] is not True:die('Rust Actions')
if js['repository_actions_permissions']['allowed_actions']!='all' or js['repository_actions_permissions']['sha_pinning_required'] is not False:die('JS Actions')
# No credential/private-key contents:metadata names/paths are allowed;secret material markers and direct token assignment are not.
all_bytes=b'\n'.join(p.read_bytes() for p in R.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
if re.search(br'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----',all_bytes):die('private key content marker')
if re.search(br'(?im)^\s*(?:GANDIV5_PERSONAL_ACCESS_TOKEN|GANDI_[A-Z_]*TOKEN|GH_TOKEN|GITHUB_TOKEN)\s*=\s*\S+',all_bytes):die('credential value assignment')
if re.search(br'\bgh[opsu]_[A-Za-z0-9]{20,}\b',all_bytes):die('GitHub token pattern')
credential_section=host.split('## credential_path_metadata_only\n',1)[1].split('\n## firewall_target_rules',1)[0]
expected_credential='kind=regular file mode=644 owner=root:root uid=0 gid=0 size=41 path=/var/lib/keys/pkgre-js-gandiv5-token\nf: /var/lib/keys/pkgre-js-gandiv5-token\ndrwxr-xr-x root root /\ndrwxr-xr-x root root var\ndrwxr-xr-x root root lib\ndrwxr-xr-x root root keys\n-rw-r--r-- root root pkgre-js-gandiv5-token\nuser::rw-\ngroup::r--\nother::r--\n\n'
if credential_section!=expected_credential:die('credential section contains unexpected material')
# Human report+validation must preserve split gate.
md=(R/'REPORT.md').read_text()
for marker in ('Verdict:packet integrity:PASS | D0 overall:BLOCKED | D1 authorized:false','mode `0644`','value not read','TOFU/continuity','D1 authorized:`false`'):
 if marker not in md:die('REPORT.md marker '+marker)
if val!={'checks':{'checksumCoverage':True,'classifications':True,'criticalValues':True,'jsonParsing':True,'noCredentialValues':True,'noSymlinks':True,'rawIdentity':True,'splitVerdict':True},'classificationCounts':{'absent':5,'blocked':13,'observed':24,'proposed':0},'d0Overall':'BLOCKED','d1Authorized':False,'packetStatus':'PASS','rawFiles':10,'schema':'pkgre-d0-live-deployment-network-validation-v1'}:die('validation.json')
print(f'PASS files={len(actual)} sha256Entries={len(manifest)} rawFiles=10 claims={len(claims)} observed=24 proposed=0 absent=5 blocked=13 d0=BLOCKED d1Authorized=false')
