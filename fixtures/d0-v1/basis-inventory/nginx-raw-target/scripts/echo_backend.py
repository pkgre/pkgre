#!/usr/bin/env python3
import argparse,base64,json,os,socket,threading,time

def hx(b): return b.hex()
def b64(b): return base64.b64encode(b).decode('ascii')

def split_head(raw):
    pos=raw.find(b'\r\n\r\n')
    if pos < 0: return raw,b''
    return raw[:pos+4],raw[pos+4:]

def parsed(head):
    lines=head[:-4].split(b'\r\n') if head.endswith(b'\r\n\r\n') else head.split(b'\r\n')
    request_line=lines[0] if lines else b''
    headers=[]
    for line in lines[1:]:
        p=line.find(b':')
        if p < 0: headers.append({'lineHex':hx(line)})
        else: headers.append({'nameHex':hx(line[:p]),'valueHex':hx(line[p+1:].lstrip(b' \t'))})
    return request_line,headers

def handle(conn,capture_dir,lock,state):
    conn.settimeout(2)
    raw=b''
    try:
        while b'\r\n\r\n' not in raw and len(raw)<131072:
            x=conn.recv(65536)
            if not x: break
            raw+=x
        head,prefetch=split_head(raw)
        line,headers=parsed(head)
        with lock:
            state[0]+=1; seq=state[0]
        item={'sequence':seq,'receivedAtNs':time.time_ns(),'rawHeadHex':hx(head),'prefetchedBodyHex':hx(prefetch),'requestLineHex':hx(line),'requestLineBase64':b64(line),'headers':headers}
        path=os.path.join(capture_dir,f'{seq:04d}.json')
        tmp=path+'.tmp'
        with open(tmp,'w',encoding='utf-8') as f: json.dump(item,f,sort_keys=True,separators=(',',':')); f.write('\n')
        os.replace(tmp,path)
        body=json.dumps(item,sort_keys=True,separators=(',',':')).encode()+b'\n'
        response=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nX-Proof-Sequence: '+str(seq).encode()+b'\r\nConnection: close\r\n\r\n'+body
        conn.sendall(response)
    except Exception as e:
        try: conn.sendall(b'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        except Exception: pass
        print(repr(e),flush=True)
    finally: conn.close()

def main():
    p=argparse.ArgumentParser();p.add_argument('--socket',required=True);p.add_argument('--captures',required=True);a=p.parse_args()
    os.makedirs(a.captures,exist_ok=True)
    try: os.unlink(a.socket)
    except FileNotFoundError: pass
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(a.socket);os.chmod(a.socket,0o600);s.listen(64)
    lock=threading.Lock();state=[0]
    print(json.dumps({'ready':True,'socket':a.socket}),flush=True)
    try:
        while True:
            c,_=s.accept();threading.Thread(target=handle,args=(c,a.captures,lock,state),daemon=True).start()
    finally: s.close()
if __name__=='__main__': main()
