import base64,datetime,gzip,hashlib,http.server,io,json,sys,tarfile
port=int(sys.argv[1]); log=sys.argv[2]
def manifest(name,version): return {'name':name,'version':version,'scripts':{'postinstall':'touch SHOULD_NOT_RUN'}}
def tgz(name,version):
 b=json.dumps(manifest(name,version),separators=(',',':')).encode(); out=io.BytesIO()
 with gzip.GzipFile(fileobj=out,mode='wb',mtime=0) as gz:
  with tarfile.open(fileobj=gz,mode='w') as t:
   i=tarfile.TarInfo('package/package.json');i.size=len(b);i.mtime=0;i.mode=0o644;t.addfile(i,io.BytesIO(b))
 return out.getvalue()
blobs={(n,v):tgz(n,v) for n in ['age-probe','pkgre-js','selection-probe'] for v in ['1.0.0','2.0.0']}
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  with open(log,'a') as f:f.write(f'{port} {self.path}\n')
  path=self.path.strip('/'); parts=path.split('/-/')
  if len(parts)==2:
   name=parts[0];version=parts[1][len(name)+1:-4];body=blobs[(name,version)];typ='application/octet-stream'
  elif path in ['age-probe','pkgre-js','selection-probe']:
   name=path;vers={}
   for v in ['1.0.0','2.0.0']:
    b=blobs[(name,v)]; vers[v]={**manifest(name,v),'dist':{'tarball':f'http://127.0.0.1:{port}/{name}/-/{name}-{v}.tgz','shasum':hashlib.sha1(b).hexdigest(),'integrity':'sha512-'+base64.b64encode(hashlib.sha512(b).digest()).decode()}}
   now=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=1)).isoformat().replace('+00:00','Z')
   body=json.dumps({'name':name,'dist-tags':{'latest':'2.0.0'},'versions':vers,'time':{'created':'2020-01-01T00:00:00.000Z','modified':now,'1.0.0':'2020-01-01T00:00:00.000Z','2.0.0':now}},separators=(',',':')).encode();typ='application/json'
  else:self.send_error(404);return
  self.send_response(200);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*a):pass
http.server.HTTPServer(('127.0.0.1',port),H).serve_forever()
