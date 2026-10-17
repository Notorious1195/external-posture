import json,unittest
from unittest.mock import patch
import zap_controller as z
class Proc:
 def poll(self):return None
 def wait(self,timeout=None):return 0
class Response:
 def __init__(self,obj):self.obj=obj
 def __enter__(self):return self
 def __exit__(self,*a):pass
 def read(self,*a):return json.dumps(self.obj).encode()
class API:
 def open(self,req,timeout=None):
  endpoint=req.full_url
  from urllib.parse import parse_qs
  params=parse_qs(req.data.decode())
  if '/setMode/' in endpoint:assert params.get('mode')==['protect']
  if '/setContextInScope/' in endpoint:assert params.get('booleanInScope')==['true']
  if '/installedAddons/' in endpoint:obj={'installedAddons':[{'id':i} for i in ('client','selenium','pscan','pscanrules')]}
  elif '/version/' in endpoint:obj={'version':'test'}
  elif '/scan/' in endpoint:obj={'scan':'0'}
  elif '/status/' in endpoint:obj={'status':'100'}
  elif '/recordsToScan/' in endpoint:obj={'recordsToScan':'0'}
  elif '/urls/' in endpoint:obj={'urls':['https://example.com/']}
  elif '/alerts/' in endpoint:obj={'alerts':[{'pluginId':'10020','name':'header','url':'https://example.com/','risk':'Low','evidence':'secret not exported'}]}
  else:obj={'Result':'OK'}
  return Response(obj)
with patch.object(z.socket,'getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',443))]),patch.object(z.shutil,'which',return_value='/usr/bin/zaproxy'),patch.object(z.subprocess,'Popen',return_value=Proc()),patch.object(z,'build_opener',return_value=API()):
 r=z.execute({'url':'https://example.com','domain':'example.com'})
 assert r['status']=='OK' and r['passive_pending']==0 and r['alerts'][0]['evidence']=='secret not exported'
 try:z.execute({'url':'https://elsewhere.com','domain':'example.com'})
 except ValueError:pass
 else:raise AssertionError('outside scope accepted')
print('PASS: daemon API lifecycle, passive completion, alert projection, out-of-scope rejected (mock)')
