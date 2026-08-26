import http.server, socketserver, sys, threading
log=sys.argv[1]; ports=list(map(int,sys.argv[2:]))
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  with open(log,'a') as f: f.write(f'{self.server.server_address[1]} {self.path}\n')
  body=b'{"error":"probe"}'
  self.send_response(404); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*a): pass
servers=[]
for p in ports:
 s=socketserver.TCPServer(('127.0.0.1',p),H); servers.append(s); threading.Thread(target=s.serve_forever,daemon=True).start()
print('ready',flush=True)
threading.Event().wait()
