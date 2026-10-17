"""No live calls: API statuses, auth redaction and in-scope redirect behavior."""
import json,types
from unittest.mock import patch
import abuse_diagnostic as api
from test_probe import Conn,run
class Response:
 def __init__(self,payload):self.payload=payload;self.status=200
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def read(self,*a):return json.dumps(self.payload).encode()
for state in ('no_result','ok','invalid_auth_key'):
 response=Response({'query_status':state,'echo':'PRIVATE_KEY'})
 opener=types.SimpleNamespace(open=lambda *a,**k:response)
 with patch.object(api.socket,'getaddrinfo',return_value=[(2,1,0,'',('8.8.8.8',443))]),patch.object(api,'build_opener',return_value=opener):
  result=api.diagnose('ThreatFox','example.com','PRIVATE_KEY')
 assert result['status']==('OK' if state in ('no_result','ok') else 'ERROR')
 assert 'PRIVATE_KEY' not in json.dumps(result)

old=Conn.getresponse
def redirected(self):
 if self.path=='/':return types.SimpleNamespace(status=302,getheaders=lambda:[('Location','/home')],read=lambda *a:b'')
 if self.path=='/home':return types.SimpleNamespace(status=200,getheaders=lambda:[('Content-Type','text/html'),('X-Frame-Options','DENY'),('X-Content-Type-Options','nosniff')],read=lambda *a:b'<html>home</html>')
 return old(self)
with patch.object(Conn,'getresponse',redirected):rows=run()
assert all(r['status']=='Evaluado' for r in rows if r['control'].startswith('W-'))
assert '/home' in next(r['evidence'] for r in rows if r['control']=='W-01')
def outside(self):
 if self.path=='/':return types.SimpleNamespace(status=302,getheaders=lambda:[('Location','https://outside.invalid/')],read=lambda *a:b'')
 return old(self)
with patch.object(Conn,'getresponse',outside):rows=run()
assert all(r['status']=='No evaluado' for r in rows if r['control'].startswith('W-'))
print('PASS: provider no_result is success, invalid auth error, no key echo, scoped redirects, outside redirect blocked')
