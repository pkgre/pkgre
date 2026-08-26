#!/usr/bin/env python3
import argparse,hashlib,json,os,socket,ssl,time
from hpack import Encoder,Decoder
from hyperframe.frame import SettingsFrame,HeadersFrame,DataFrame
PREFACE=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def frame_bytes(frame):return frame.serialize()
def build_request(c):
    enc=Encoder();hs=[(bytes.fromhex(a),bytes.fromhex(b)) for a,b in c['headersHex']]
    sf=SettingsFrame(0)
    hf=HeadersFrame(1);hf.data=enc.encode(hs,huffman=False);hf.flags.add('END_HEADERS')
    data=bytes.fromhex(c.get('dataHex',''))
    trailers=[(bytes.fromhex(a),bytes.fromhex(b)) for a,b in c.get('trailersHex',[])]
    if c.get('endStream',True) and not data and not trailers:hf.flags.add('END_STREAM')
    out=PREFACE+frame_bytes(sf)+frame_bytes(hf)
    if data:
        df=DataFrame(1);df.data=data
        if not trailers:df.flags.add('END_STREAM')
        out+=frame_bytes(df)
    if trailers:
        tf=HeadersFrame(1);tf.data=enc.encode(trailers,huffman=False);tf.flags.add('END_HEADERS');tf.flags.add('END_STREAM');out+=frame_bytes(tf)
    elif not data and not c.get('endStream',True):
        df=DataFrame(1);df.data=b'';df.flags.add('END_STREAM');out+=frame_bytes(df)
    return out,hs

def parse_frames(raw):
    frames=[];i=0
    while i+9<=len(raw):
        n=int.from_bytes(raw[i:i+3],'big');typ=raw[i+3];flags=raw[i+4];sid=int.from_bytes(raw[i+5:i+9],'big')&0x7fffffff
        if i+9+n>len(raw):break
        data=raw[i+9:i+9+n];frames.append({'type':typ,'flags':flags,'stream':sid,'length':n,'dataHex':data.hex()});i+=9+n
    if i<len(raw):frames.append({'trailingHex':raw[i:].hex()})
    return frames

def header_fragment(fr):
    data=bytes.fromhex(fr['dataHex']);flags=fr['flags'];i=0;end=len(data)
    if flags&0x8:
        pad=data[0];i=1;end-=pad
    if flags&0x20:i+=5
    return data[i:end]

def decode_response(frames):
    dec=Decoder();blocks=[];body=b'';current=None;errors=[];end=False
    for fr in frames:
        if 'type' not in fr:continue
        t=fr['type'];sid=fr['stream'];flags=fr['flags'];data=bytes.fromhex(fr['dataHex'])
        if t==1 and sid==1:
            current=header_fragment(fr)
            if flags&0x4:
                try:blocks.append([(a.hex(),b.hex()) for a,b in dec.decode(current,raw=True)])
                except Exception as e:errors.append('hpack:'+repr(e))
                current=None
            if flags&0x1:end=True
        elif t==9 and sid==1 and current is not None:
            current+=data
            if flags&0x4:
                try:blocks.append([(a.hex(),b.hex()) for a,b in dec.decode(current,raw=True)])
                except Exception as e:errors.append('hpack:'+repr(e))
                current=None
        elif t==0 and sid==1:
            if flags&0x8:
                pad=data[0];data=data[1:len(data)-pad]
            body+=data
            if flags&0x1:end=True
        elif t==3 and sid==1:errors.append('rst_stream:'+str(int.from_bytes(data[:4],'big')))
        elif t==7:errors.append('goaway:'+str(int.from_bytes(data[4:8],'big') if len(data)>=8 else -1))
    statuses=[];seqs=[]
    for block in blocks:
        for a,b in block:
            name=bytes.fromhex(a).lower();value=bytes.fromhex(b)
            if name==b':status':
                try:statuses.append(int(value))
                except:pass
            if name==b'x-proof-sequence':
                try:seqs.append(int(value))
                except:pass
    return {'headerBlocksHex':blocks,'bodyHex':body.hex(),'statuses':statuses,'finalStatus':statuses[-1] if statuses else None,'backendSequence':seqs[-1] if seqs else None,'decodeErrors':errors,'endStreamSeen':end}

def exchange(port,raw,sni):
    base=socket.create_connection(('127.0.0.1',port),2);base.settimeout(.7)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ctx.set_alpn_protocols(['h2'])
    s=ctx.wrap_socket(base,server_hostname=sni);tls={'version':s.version(),'cipher':list(s.cipher() or ()),'alpn':s.selected_alpn_protocol(),'peerCertificateSha256':hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()}
    s.sendall(raw);out=b''
    while len(out)<1048576:
        try:
            b=s.recv(65536)
            if not b:break
            out+=b;fs=parse_frames(out)
            if any(f.get('stream')==1 and ((f.get('type') in (0,1) and f.get('flags',0)&1) or f.get('type')==3) for f in fs):break
            if any(f.get('type')==7 for f in fs):break
        except socket.timeout:break
    s.close();return out,tls

def main():
    p=argparse.ArgumentParser();p.add_argument('--cases',required=True);p.add_argument('--out',required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--mode',required=True);a=p.parse_args()
    cases=json.load(open(a.cases));os.makedirs(a.out,exist_ok=True);summary=[]
    for c in cases:
        raw,hs=build_request(c);sni=c.get('sni','registry.test');sni=None if sni is None else str(sni)
        try:
            response,tls=exchange(a.port,raw,sni);frames=parse_frames(response);x={'id':c['id'],'mode':a.mode,'port':a.port,'sni':sni,'tls':tls,'requestHex':raw.hex(),'requestHeadersHex':[[u.hex(),v.hex()] for u,v in hs],'responseHex':response.hex(),'frames':frames,'note':c.get('note','')};x.update(decode_response(frames))
        except Exception as e:x={'id':c['id'],'mode':a.mode,'port':a.port,'sni':sni,'requestHex':raw.hex(),'requestHeadersHex':[[u.hex(),v.hex()] for u,v in hs],'exception':repr(e),'finalStatus':None,'backendSequence':None,'note':c.get('note','')}
        with open(os.path.join(a.out,c['id']+'.json'),'w') as f:json.dump(x,f,sort_keys=True,separators=(',',':'));f.write('\n')
        summary.append(x);time.sleep(.01)
    with open(os.path.join(a.out,'summary.json'),'w') as f:json.dump(summary,f,indent=2,sort_keys=True);f.write('\n')
if __name__=='__main__':main()
