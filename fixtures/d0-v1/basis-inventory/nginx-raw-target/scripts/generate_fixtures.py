#!/usr/bin/env python3
import json,os
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def H(name,value): return [name.encode().hex(),value.encode().hex()]
def HB(name,value): return [name.hex(),value.hex()]
def S(case,sni): case['sni']=sni;return case
def h1(i,target=b'/',method=b'GET',headers=(),tail=b'',note=''):
    base=[(b'Host',b'registry.test'),(b'Connection',b'close'),(b'X-Proof-Case',i.encode())]
    return {'id':i,'methodHex':method.hex(),'targetHex':target.hex(),'versionHex':b'HTTP/1.1'.hex(),'headersHex':[[a.hex(),b.hex()] for a,b in base+list(headers)],'tailHex':tail.hex(),'note':note}
def h2(i,path=b'/',method=b'GET',headers=(),authority=b'registry.test',scheme=b'http',end_stream=True,data=b'',raw_order=None,note=''):
    hs=raw_order if raw_order is not None else [(b':method',method),(b':scheme',scheme),(b':authority',authority),(b':path',path)]+list(headers)+[(b'x-proof-case',i.encode())]
    return {'id':i,'headersHex':[[a.hex(),b.hex()] for a,b in hs],'endStream':end_stream,'dataHex':data.hex(),'note':note}

H1=[]
# Request-target bytes: normal, normalization-sensitive, percent/UTF-8/path grammar.
targets=[
('origin_root',b'/'),('origin_simple',b'/route-a/pkg'),('query_empty',b'/pkg?'),('query_value',b'/pkg?a=%2F&b=1'),
('duplicate_slash_inner',b'/route-a//pkg'),('duplicate_slash_leading',b'//route-a/pkg'),('triple_slash',b'///route-a///pkg'),
('raw_backslash',b'/route-a\\pkg'),('encoded_slash_upper',b'/route-a%2Fpkg'),('encoded_slash_lower',b'/route-a%2fpkg'),
('encoded_backslash_upper',b'/route-a%5Cpkg'),('encoded_backslash_lower',b'/route-a%5cpkg'),
('dot_raw',b'/route-a/./pkg'),('dotdot_raw',b'/route-a/../pkg'),('dot_encoded',b'/route-a/%2E/pkg'),('dotdot_encoded',b'/route-a/%2e%2E/pkg'),
('double_encoded_slash',b'/route-a%252Fpkg'),('double_encoded_dotdot',b'/route-a/%252e%252e/pkg'),
('malformed_percent_bare',b'/pkg%'),('malformed_percent_short',b'/pkg%2'),('malformed_percent_hex',b'/pkg%GG'),
('utf8_valid',b'/caf\xc3\xa9'),('utf8_invalid_cont',b'/bad\x80'),('utf8_invalid_overlong',b'/bad\xc0\xaf'),('utf8_invalid_truncated',b'/bad\xe2\x82'),
('nul_raw',b'/a\x00b'),('nul_encoded',b'/a%00b'),('raw_fragment',b'/pkg#frag'),('encoded_fragment',b'/pkg%23frag'),
('scoped_exact',b'/%40scope%2Fpkg'),('scoped_lower_slash',b'/%40scope%2fpkg'),('scoped_raw_at_encoded_slash',b'/@scope%2Fpkg'),
('scoped_encoded_at_raw_slash',b'/%40scope/pkg'),('scoped_raw',b'/@scope/pkg'),('scoped_double',b'/%2540scope%252Fpkg'),
('scoped_mixed_hex',b'/%4Ascope%2Fpkg'),('scoped_encoded_separator_name',b'/%40sc%2Fope%2Fpkg'),
]
for i,t in targets:H1.append(h1(i,t))
H1 += [
 h1('absolute_http',b'http://registry.test/route-a/pkg?x=1'),
 h1('absolute_https_upper',b'HTTPS://registry.test/route-a/%2Fpkg'),
 h1('absolute_host_mismatch',b'http://other.test/pkg'),
 h1('authority_connect',b'registry.test:443',method=b'CONNECT'),
 h1('asterisk_options',b'*',method=b'OPTIONS'),
 h1('asterisk_get',b'*',method=b'GET'),
 h1('origin_post',b'/pkg',method=b'POST'),
 h1('origin_head',b'/pkg',method=b'HEAD'),
 h1('private_overwrite',b'/pkg',headers=((b'X-Pkgre-Edge-Raw-Target',b'caller-target'),(b'X-Pkgre-Edge-Request-Form',b'caller-form'))),
 h1('duplicate_host_same',b'/pkg',headers=((b'Host',b'registry.test'),)),
 h1('duplicate_host_different',b'/pkg',headers=((b'Host',b'evil.test'),)),
 h1('comma_host',b'/pkg',headers=((b'Host',b'registry.test,evil.test'),)),
 h1('host_with_port',b'/pkg',headers=((b'Host',b'registry.test:80'),)),
 h1('duplicate_generic',b'/pkg',headers=((b'X-Test',b'one'),(b'X-Test',b'two'))),
 h1('obs_fold_generic',b'/pkg',headers=((b'X-Test',b'one'),(b'\ttwo',b''))),
 h1('invalid_header_name_space',b'/pkg',headers=((b'Bad Name',b'value'),)),
 h1('invalid_header_name_ctl',b'/pkg',headers=((b'Bad\x01Name',b'value'),)),
 h1('hop_connection',b'/pkg',headers=((b'Connection',b'X-Hop'),(b'X-Hop',b'hop-sentinel'))),
 h1('te_trailers_header',b'/pkg',headers=((b'TE',b'trailers'),)),
 h1('expect_no_body',b'/pkg',headers=((b'Expect',b'100-continue'),)),
 h1('trailer_header_no_body',b'/pkg',headers=((b'Trailer',b'X-Trail'),)),
 h1('overlong_header',b'/pkg',headers=((b'X-Large',b'a'*9000),)),
 h1('many_headers_256',b'/pkg',headers=tuple((f'X-H-{n:04d}'.encode(),b'a') for n in range(256))),
 h1('many_headers_4096',b'/pkg',headers=tuple((f'X-H-{n:04d}'.encode(),b'a') for n in range(4096))),
 h1('content_length_over_limit',b'/pkg',headers=((b'Content-Length',b'2048'),),tail=b'A'*2048),
 h1('content_length_zero',b'/pkg',headers=((b'Content-Length',b'0'),)),
 h1('content_length_body',b'/pkg',headers=((b'Content-Length',b'4'),),tail=b'DATA'),
 h1('expect_body',b'/pkg',headers=((b'Content-Length',b'4'),(b'Expect',b'100-continue')),tail=b'DATA'),
 h1('chunked_body',b'/pkg',headers=((b'Transfer-Encoding',b'chunked'),),tail=b'4\r\nDATA\r\n0\r\n\r\n'),
 h1('chunked_trailer',b'/pkg',headers=((b'Transfer-Encoding',b'chunked'),(b'Trailer',b'X-Trail')),tail=b'1\r\nA\r\n0\r\nX-Trail: trailer-sentinel\r\n\r\n'),
 h1('cl_and_te',b'/pkg',headers=((b'Content-Length',b'4'),(b'Transfer-Encoding',b'chunked')),tail=b'0\r\n\r\n'),
 h1('duplicate_cl_same',b'/pkg',headers=((b'Content-Length',b'0'),(b'Content-Length',b'0'))),
 h1('duplicate_cl_different',b'/pkg',headers=((b'Content-Length',b'0'),(b'Content-Length',b'1')),tail=b'X'),
 h1('overlong_target',b'/'+b'a'*9000),
]
# Raw request-line/header cases not representable by normal construction.
H1.append({'id':'raw_space_target','rawHex':b'GET /a b HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\nX-Proof-Case: raw_space_target\r\n\r\n'.hex(),'note':'space inside target'})
H1.append({'id':'single_host_port','rawHex':b'GET /pkg HTTP/1.1\r\nHost: registry.test:80\r\nConnection: close\r\nX-Proof-Case: single_host_port\r\n\r\n'.hex(),'note':''})
H1.append({'id':'single_host_comma','rawHex':b'GET /pkg HTTP/1.1\r\nHost: registry.test,evil.test\r\nConnection: close\r\nX-Proof-Case: single_host_comma\r\n\r\n'.hex(),'note':''})
H1.append({'id':'single_host_upper','rawHex':b'GET /pkg HTTP/1.1\r\nHost: REGISTRY.TEST\r\nConnection: close\r\nX-Proof-Case: single_host_upper\r\n\r\n'.hex(),'note':''})
H1.append({'id':'target_del','rawHex':b'GET /a\x7fb HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\nX-Proof-Case: target_del\r\n\r\n'.hex(),'note':''})
H1.append({'id':'target_ctl','rawHex':b'GET /a\x01b HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\nX-Proof-Case: target_ctl\r\n\r\n'.hex(),'note':''})
H1.append({'id':'missing_host','rawHex':b'GET /pkg HTTP/1.1\r\nConnection: close\r\nX-Proof-Case: missing_host\r\n\r\n'.hex(),'note':''})
H1 += [
 S(h1('sni_missing',b'/pkg'),None),
 S(h1('sni_unknown',b'/pkg'),'evil.test'),
 S(h1('sni_upper',b'/pkg'),'REGISTRY.TEST'),
 S(h1('sni_host_mismatch',b'/pkg',headers=((b'Host',b'evil.test'),)),'registry.test'),
]

H2=[]
for i,t in targets:
    # H2 malformed/very invalid cases retained; frame-level outcome is evidence.
    H2.append(h2('h2_'+i,t))
H2 += [
 h2('h2_absolute_path',b'http://registry.test/route-a/pkg?x=1'),
 h2('h2_asterisk_options',b'*',method=b'OPTIONS'),
 h2('h2_asterisk_get',b'*'),
 h2('h2_post',b'/pkg',method=b'POST'),
 h2('h2_private_overwrite',b'/pkg',headers=((b'x-pkgre-edge-raw-target',b'caller-target'),(b'x-pkgre-edge-request-form',b'caller-form'))),
 h2('h2_host_same',b'/pkg',headers=((b'host',b'registry.test'),)),
 h2('h2_host_mismatch',b'/pkg',headers=((b'host',b'evil.test'),)),
 h2('h2_duplicate_host',b'/pkg',headers=((b'host',b'registry.test'),(b'host',b'registry.test'))),
 h2('h2_duplicate_generic',b'/pkg',headers=((b'x-test',b'one'),(b'x-test',b'two'))),
 h2('h2_connection_header',b'/pkg',headers=((b'connection',b'close'),)),
 h2('h2_te_trailers',b'/pkg',headers=((b'te',b'trailers'),)),
 h2('h2_expect_no_body',b'/pkg',headers=((b'expect',b'100-continue'),)),
 h2('h2_overlong_header',b'/pkg',headers=((b'x-large',b'a'*9000),)),
 h2('h2_overlong_path',b'/'+b'a'*9000),
 h2('h2_content_length_over_limit',b'/pkg',headers=((b'content-length',b'2048'),),end_stream=False,data=b'A'*2048),
 h2('h2_content_length_zero',b'/pkg',headers=((b'content-length',b'0'),)),
 h2('h2_content_length_body',b'/pkg',headers=((b'content-length',b'4'),),end_stream=False,data=b'DATA'),
 h2('h2_expect_body',b'/pkg',headers=((b'content-length',b'4'),(b'expect',b'100-continue')),end_stream=False,data=b'DATA'),
 h2('h2_trailer_body',b'/pkg',headers=((b'trailer',b'x-trail'),),end_stream=False,data=b'DATA'),
 {'id':'h2_actual_trailer','headersHex':[[a.hex(),b.hex()] for a,b in [(b':method',b'GET'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b':path',b'/pkg'),(b'trailer',b'x-trail'),(b'x-proof-case',b'h2_actual_trailer')]],'endStream':False,'dataHex':b'DATA'.hex(),'trailersHex':[[b'x-trail'.hex(),b'trailer-sentinel'.hex()]],'note':'actual trailing HEADERS'},
 h2('h2_transfer_encoding',b'/pkg',headers=((b'transfer-encoding',b'chunked'),)),
 h2('h2_duplicate_content_length',b'/pkg',headers=((b'content-length',b'0'),(b'content-length',b'0'))),
 h2('h2_authority_port',b'/pkg',authority=b'registry.test:80'),
 h2('h2_authority_upper',b'/pkg',authority=b'REGISTRY.TEST'),
 h2('h2_missing_path',raw_order=[(b':method',b'GET'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b'x-proof-case',b'h2_missing_path')]),
 h2('h2_empty_path',raw_order=[(b':method',b'GET'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b':path',b''),(b'x-proof-case',b'h2_empty_path')]),
 h2('h2_duplicate_path',raw_order=[(b':method',b'GET'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b':path',b'/one'),(b':path',b'/two'),(b'x-proof-case',b'h2_duplicate_path')]),
 h2('h2_duplicate_authority',raw_order=[(b':method',b'GET'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b':authority',b'registry.test'),(b':path',b'/pkg'),(b'x-proof-case',b'h2_duplicate_authority')]),
 h2('h2_pseudo_after_regular',raw_order=[(b':method',b'GET'),(b'x-test',b'one'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b':path',b'/pkg'),(b'x-proof-case',b'h2_pseudo_after_regular')]),
 h2('h2_uppercase_header',raw_order=[(b':method',b'GET'),(b':scheme',b'http'),(b':authority',b'registry.test'),(b':path',b'/pkg'),(b'X-Test',b'one'),(b'x-proof-case',b'h2_uppercase_header')]),
 h2('h2_connect_authority',raw_order=[(b':method',b'CONNECT'),(b':authority',b'registry.test:443'),(b'x-proof-case',b'h2_connect_authority')]),
]
for fn,obj in [('h1-cases.json',H1),('h2-cases.json',H2)]:
    with open(os.path.join(ROOT,'fixtures',fn),'w') as f:json.dump(obj,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({'h1':len(H1),'h2':len(H2)}))
