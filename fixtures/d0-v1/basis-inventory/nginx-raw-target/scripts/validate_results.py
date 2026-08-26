#!/usr/bin/env python3
import hashlib,json,os,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
errors=[];checks=[]
def check(name,ok,detail=None):
 checks.append({'name':name,'ok':bool(ok),'detail':detail})
 if not ok:errors.append(name+((': '+str(detail)) if detail is not None else ''))
def load(p):
 try:return json.loads(p.read_text())
 except Exception as e:check('json:'+str(p.relative_to(ROOT)),False,repr(e));return None
def target(case,proto):
 if proto=='h1':
  if 'rawHex' in case:
   parts=bytes.fromhex(case['rawHex']).split(b'\r\n',1)[0].split(b' ')
   return parts[1] if len(parts)==3 else None
  return bytes.fromhex(case['targetHex'])
 vals=[bytes.fromhex(v) for n,v in case['headersHex'] if bytes.fromhex(n)==b':path']
 return vals[0] if len(vals)==1 else None
def hdrs(cap):return [(bytes.fromhex(h['nameHex']).lower(),bytes.fromhex(h.get('valueHex',''))) for h in cap['headers'] if 'nameHex'in h]
def vals(cap,name):return [v for n,v in hdrs(cap) if n==name]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
cases={p:{c['id']:c for c in load(ROOT/f'fixtures/{p}-cases.json')} for p in ['h1','h2']}
check('fixture-counts',list(map(len,cases.values()))==[82,68],{p:len(v) for p,v in cases.items()})
check('fixture-ids-unique',all(len(v)==len(set(v)) for v in cases.values()))
referenced=[];forwarded_counts={};status_counts={};preserved={};normalization_distinct={}
for proto in ['h1','h2']:
 for mode in ['observe','policy']:
  d=ROOT/f'results/{proto}-{mode}'; summary=load(d/'summary.json') or []
  ids=[x.get('id') for x in summary]; expected=list(cases[proto])
  check(f'{proto}-{mode}:summary-order-and-count',ids==expected,{'actual':len(ids),'expected':len(expected)})
  files={p.stem for p in d.glob('*.json') if p.name!='summary.json'}
  check(f'{proto}-{mode}:case-file-set',files==set(expected),{'actual':len(files),'expected':len(expected)})
  fwd=0;exact=0;distinct=0;statuses={}
  for x in summary:
   cid=x['id']; individual=load(d/(cid+'.json'))
   check(f'{proto}-{mode}:{cid}:summary-equals-file',x==individual)
   st=x.get('finalStatus');statuses[str(st)]=statuses.get(str(st),0)+1
   seq=x.get('backendSequence')
   if seq is None:continue
   fwd+=1;referenced.append(seq);cap=load(ROOT/f'results/backend/{seq:04d}.json')
   check(f'{proto}-{mode}:{cid}:backend-capture-exists',cap is not None)
   if cap is None:continue
   check(f'{proto}-{mode}:{cid}:sequence',cap.get('sequence')==seq)
   backend_line=bytes.fromhex(cap['requestLineHex']);backend_parts=backend_line.split(b' ')
   check(f'{proto}-{mode}:{cid}:private-boundary-http11',len(backend_parts)==3 and backend_parts[2]==b'HTTP/1.1')
   check(f'{proto}-{mode}:{cid}:no-body',cap.get('prefetchedBodyHex')=='')
   expected_target=target(cases[proto][cid],proto);raw=vals(cap,b'x-pkgre-edge-raw-target')
   match=expected_target is not None and raw==[expected_target];exact+=int(match)
   check(f'{proto}-{mode}:{cid}:raw-target-exact',match,{'expectedHex':None if expected_target is None else expected_target.hex(),'actualHex':[v.hex() for v in raw]})
   forms=vals(cap,b'x-pkgre-edge-request-form');expected_form=('h1-absolute' if proto=='h1' and cid.startswith('absolute_') else proto+'-origin')
   check(f'{proto}-{mode}:{cid}:request-form-protected',forms==[expected_form.encode()],{'actual':[v.decode('latin1') for v in forms]})
   names=[n for n,v in hdrs(cap)]
   check(f'{proto}-{mode}:{cid}:protected-fields-singleton',names.count(b'x-pkgre-edge-raw-target')==1 and names.count(b'x-pkgre-edge-request-form')==1)
   check(f'{proto}-{mode}:{cid}:input-headers-not-forwarded',not any(n in names for n in [b'x-test',b'x-hop',b'te',b'trailer',b'expect',b'transfer-encoding']))
   norm=vals(cap,b'x-pkgre-diag-normalized-uri')
   if norm and expected_target != norm[0]:distinct+=1
  forwarded_counts[f'{proto}-{mode}']=fwd;status_counts[f'{proto}-{mode}']=statuses;preserved[f'{proto}-{mode}']=exact;normalization_distinct[f'{proto}-{mode}']=distinct
  check(f'{proto}-{mode}:all-forwarded-preserved',fwd==exact,{'forwarded':fwd,'exact':exact})
check('forwarded-counts',forwarded_counts=={'h1-observe':55,'h1-policy':36,'h2-observe':47,'h2-policy':36},forwarded_counts)
backend_files=sorted((ROOT/'results/backend').glob('*.json'));seqs=[int(p.stem) for p in backend_files]
check('backend-sequence-contiguous',seqs==list(range(1,175)),{'count':len(seqs),'first':seqs[:1],'last':seqs[-1:]})
check('backend-each-referenced-once',sorted(referenced)==seqs and len(referenced)==len(set(referenced)),{'references':len(referenced),'captures':len(seqs)})
# Required parser/form/body/header/limit outcomes; anything reaching backend violates the boundary.
def item(proto,mode,cid):return load(ROOT/f'results/{proto}-{mode}/{cid}.json')
def stopped(proto,mode,ids):return all(item(proto,mode,i).get('backendSequence') is None for i in ids)
check('h1-request-form-policy',stopped('h1','policy',['absolute_http','absolute_https_upper','absolute_host_mismatch','authority_connect','asterisk_options','asterisk_get']))
check('h2-request-form-policy',stopped('h2','policy',['h2_absolute_path','h2_asterisk_options','h2_asterisk_get','h2_connect_authority','h2_missing_path','h2_empty_path','h2_duplicate_path','h2_duplicate_authority']))
check('h1-query-method-body-policy',stopped('h1','policy',['query_empty','query_value','origin_post','expect_no_body','trailer_header_no_body','content_length_over_limit','content_length_zero','content_length_body','expect_body','chunked_body','chunked_trailer','cl_and_te','duplicate_cl_same','duplicate_cl_different']))
check('h2-query-method-body-policy',stopped('h2','policy',['h2_query_empty','h2_query_value','h2_post','h2_expect_no_body','h2_content_length_over_limit','h2_content_length_zero','h2_content_length_body','h2_expect_body','h2_trailer_body','h2_actual_trailer','h2_transfer_encoding','h2_duplicate_content_length']))
check('h1-malformed-host-header-limits',stopped('h1','observe',['malformed_percent_bare','malformed_percent_short','malformed_percent_hex','nul_raw','nul_encoded','duplicate_host_same','duplicate_host_different','comma_host','host_with_port','obs_fold_generic','invalid_header_name_space','invalid_header_name_ctl','overlong_header','many_headers_4096','cl_and_te','duplicate_cl_same','duplicate_cl_different','overlong_target','raw_space_target','target_del','target_ctl','missing_host']))
check('h2-pseudoheader-header-limits',stopped('h2','observe',['h2_malformed_percent_bare','h2_malformed_percent_short','h2_malformed_percent_hex','h2_nul_raw','h2_nul_encoded','h2_absolute_path','h2_asterisk_options','h2_asterisk_get','h2_host_mismatch','h2_duplicate_host','h2_overlong_header','h2_overlong_path','h2_duplicate_content_length','h2_missing_path','h2_empty_path','h2_duplicate_path','h2_duplicate_authority','h2_uppercase_header','h2_connect_authority']))
check('sni-policy-rejects-missing-unknown',all('SSLError' in item('h1','policy',i).get('exception','') and item('h1','policy',i).get('backendSequence') is None for i in ['sni_missing','sni_unknown']))
check('private-field-overwrite-h1',all(vals(load(ROOT/f"results/backend/{item('h1',m,'private_overwrite')['backendSequence']:04d}.json"),b'x-pkgre-edge-raw-target')==[b'/pkg'] and vals(load(ROOT/f"results/backend/{item('h1',m,'private_overwrite')['backendSequence']:04d}.json"),b'x-pkgre-edge-request-form')==[b'h1-origin'] for m in ['observe','policy']))
check('private-field-overwrite-h2',all(vals(load(ROOT/f"results/backend/{item('h2',m,'h2_private_overwrite')['backendSequence']:04d}.json"),b'x-pkgre-edge-raw-target')==[b'/pkg'] and vals(load(ROOT/f"results/backend/{item('h2',m,'h2_private_overwrite')['backendSequence']:04d}.json"),b'x-pkgre-edge-request-form')==[b'h2-origin'] for m in ['observe','policy']))
tool=(ROOT/'results/toolchain.txt').read_text();m=dict(line.split('=',1) for line in tool.splitlines() if '=' in line and not line.startswith('nginxV='))
check('nginx-binary-hash',m.get('nginxBinSha256')=='8d61b66b1b71e5021d1d3e6378f9e400f83f897d292a7fb535c37556d85787c1')
check('nginx-version','nginxV=nginx version: nginx/1.30.4' in tool)
check('nginx-derivation',m.get('nginxDrv')=='/nix/store/7d0a3gqn59b9j58gly11b7qaisch0ikk-nginx-1.30.4.drv')
check('effective-config-hash',m.get('effectiveNginxConfigSha256')==sha(ROOT/'results/nginx.conf'))
check('template-config-hash',m.get('nginxTemplateSha256')==sha(ROOT/'config/nginx.conf.template'))
check('unix-socket-mode',m.get('backendSocketMode')=='600')
check('nginx-config-test','test is successful' in (ROOT/'results/nginx-test.log').read_text())
# Payload hash inventory: validation/manifests/reports excluded to avoid self-reference.
excluded={'REPORT.md','inventory.json','summary.json','validation.json','SHA256SUMS'}
payload=[]
for p in sorted(x for x in ROOT.rglob('*') if x.is_file() and x.relative_to(ROOT).as_posix() not in excluded):payload.append({'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)})
out={'schema':'d0-nginx-raw-target-validation-v1','ok':not errors,'errors':errors,'metrics':{'fixtureCounts':{p:len(v) for p,v in cases.items()},'forwardedCounts':forwarded_counts,'statusCounts':status_counts,'backendCaptureCount':len(seqs),'exactRawTargetCount':preserved,'rawDifferentFromNormalizedDiagnosticCount':normalization_distinct,'payloadFileCount':len(payload)},'checks':checks,'payload':payload}
(ROOT/'validation.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps({'ok':out['ok'],'checks':len(checks),'errors':len(errors),'payloadFiles':len(payload)}))
sys.exit(0 if out['ok'] else 1)
