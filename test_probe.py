"""Public probes: timeout is unknown, headers/certificate/DNS measured separately."""
import io,json,sys,types
from contextlib import redirect_stdout
from unittest.mock import patch
from posture_probe import SCRIPT
class Conn:
 def __init__(self,*a,**k):pass
 def request(self,*a,**k):self.path=a[1]
 def getresponse(self):
  path=self.path;body='<html>home</html>' if path=='/' else 'Not found'
  status=200 if path=='/' else 404
  return types.SimpleNamespace(status=status,read=lambda *a:body.encode(),getheaders=lambda:[('Content-Type','text/html'),('X-Frame-Options','DENY'),('X-Content-Type-Options','nosniff')])
 def close(self):pass
class TLS:
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def getpeercert(self):return {'notAfter':'Jan 1 00:00:00 2030 GMT'}
 def version(self):return 'TLSv1.3'
class CertError(Exception):pass

def run(failure=False,issuer=False):
 sock=types.SimpleNamespace(SOCK_STREAM=1,getaddrinfo=lambda *a,**k:[(2,1,0,'',('8.8.8.8',443))])
 def connect(*a,**k):
  if failure:raise TimeoutError('timeout')
  return TLS()
 sock.create_connection=connect
 def wrap(*a,**k):
  if issuer:
   exc=CertError('unable to get local issuer certificate');exc.verify_code=20;raise exc
  return TLS()
 ssl=types.SimpleNamespace(create_default_context=lambda:types.SimpleNamespace(wrap_socket=wrap),_create_unverified_context=lambda:types.SimpleNamespace(wrap_socket=lambda *a,**k:TLS()),SSLCertVerificationError=CertError)
 client=types.ModuleType('http.client');client.HTTPConnection=client.HTTPSConnection=Conn
 http=types.ModuleType('http');http.client=client
 def dig(argv,**k):
  dm=argv[-2].startswith('_dmarc')
  txt='v=DMARC1; p=reject' if dm else 'v=spf1 -all'
  return types.SimpleNamespace(returncode=0,stdout=';; ->>HEADER<<- status: NOERROR\nexample.com.\t60\tIN\tTXT\t"'+txt+'"\n',stderr='')
 subprocess=types.SimpleNamespace(run=dig)
 output=io.StringIO()
 with patch.dict(sys.modules,{'socket':sock,'ssl':ssl,'http':http,'http.client':client,'subprocess':subprocess}),patch('sys.stdin',io.StringIO(json.dumps({'domain':'example.com','urls':['https://example.com']}))),redirect_stdout(output):
  exec(compile(SCRIPT,'remote-probe','exec'),{})
 return json.loads(output.getvalue())
rows=run();assert all(r['status']=='Evaluado' and r['penalty']==0 for r in rows)
rows=run(True);assert all(r['status']=='No evaluado' for r in rows if r['control'].startswith(('W-','T-')))
print('PASS: public probe successes and timeout/unknown separation')

rows=run(issuer=True)
assert next(r for r in rows if r['control']=='T-01')['status']=='No evaluado'
assert next(r for r in rows if r['control']=='W-01')['status']=='Evaluado'
def exposed(self):
 bodies={'/':'<html>home</html>','/.git/HEAD':'ref: refs/heads/main','/.env':'DB_PASSWORD=PRIVATE_EXAMPLE_VALUE','/phpinfo.php':'phpinfo() PHP Version Configuration'}
 body=bodies.get(self.path,'Not found');status=200 if self.path in bodies else 404
 return types.SimpleNamespace(status=status,read=lambda *a:body.encode(),getheaders=lambda:[('Content-Type','text/html'),('X-Frame-Options','DENY'),('X-Content-Type-Options','nosniff')])
with patch.object(Conn,'getresponse',exposed):rows=run()
assert all(r['penalty']>0 for r in rows if r['control'].startswith('V-'))
assert 'PRIVATE_EXAMPLE_VALUE' not in json.dumps(rows)
print('PASS: ambiguous issuer stays unknown, HTTP checks continue, exposure signatures confirmed, secret values omitted')
