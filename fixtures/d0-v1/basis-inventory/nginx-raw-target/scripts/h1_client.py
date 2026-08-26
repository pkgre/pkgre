#!/usr/bin/env python3
import argparse,hashlib,json,os,re,socket,ssl,time

def make_raw(c):
    if 'rawHex' in c:return bytes.fromhex(c['rawHex'])
    line=bytes.fromhex(c['methodHex'])+b' '+bytes.fromhex(c['targetHex'])+b' '+bytes.fromhex(c['versionHex'])+b'\r\n'
    hs=b''.join(bytes.fromhex(a)+b': '+bytes.fromhex(b)+b'\r\n' for a,b in c['headersHex'])
    return line+hs+b'\r\n'+bytes.fromhex(c.get('tailHex',''))
def exchange(host,port,raw,sni):
    base=socket.create_connection((host,port),2);base.settimeout(.7)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ctx.set_alpn_protocols(['http/1.1'])
    s=ctx.wrap_socket(base,server_hostname=sni);tls={'version':s.version(),'cipher':list(s.cipher() or ()),'alpn':s.selected_alpn_protocol(),'peerCertificateSha256':hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()}
    s.sendall(raw);out=b''
    while True:
        try:
            b=s.recv(65536)
            if not b:break
            out+=b
        except socket.timeout:break
    s.close();return out,tls
def result(c,raw,response,mode,port,sni,tls):
    statuses=[int(x) for x in re.findall(rb'HTTP/1[.][01] ([0-9]{3})',response)]
    seqs=[int(x) for x in re.findall(rb'(?i)\r\nX-Proof-Sequence: ([0-9]+)\r\n',response)]
    return {'id':c['id'],'mode':mode,'port':port,'sni':sni,'tls':tls,'requestHex':raw.hex(),'responseHex':response.hex(),'statuses':statuses,'finalStatus':statuses[-1] if statuses else None,'backendSequence':seqs[-1] if seqs else None,'note':c.get('note','')}
def main():
    p=argparse.ArgumentParser();p.add_argument('--cases',required=True);p.add_argument('--out',required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--mode',required=True);a=p.parse_args()
    cases=json.load(open(a.cases));os.makedirs(a.out,exist_ok=True);summary=[]
    for c in cases:
        raw=make_raw(c);sni=c.get('sni','registry.test');sni=None if sni is None else str(sni)
        try:r,tls=exchange('127.0.0.1',a.port,raw,sni);x=result(c,raw,r,a.mode,a.port,sni,tls)
        except Exception as e:x={'id':c['id'],'mode':a.mode,'port':a.port,'sni':sni,'requestHex':raw.hex(),'exception':repr(e),'finalStatus':None,'backendSequence':None,'note':c.get('note','')}
        with open(os.path.join(a.out,c['id']+'.json'),'w') as f:json.dump(x,f,sort_keys=True,separators=(',',':'));f.write('\n')
        summary.append(x);time.sleep(.01)
    with open(os.path.join(a.out,'summary.json'),'w') as f:json.dump(summary,f,indent=2,sort_keys=True);f.write('\n')
if __name__=='__main__':main()
