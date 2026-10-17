from copy import deepcopy
from unittest.mock import patch
from posture import calculate,check
import zap_controller as zap
import sys,types
try:import requests
except ImportError:
 m=types.ModuleType("requests");m.RequestException=Exception;sys.modules["requests"]=m
import public_sources as ps
base={'domain':'example.com','hosts':[],'results':[],'manual_checks':[check('D-01','example.com','Evaluado',0,'SPF verified')]}
p=calculate(base);d=next(d for d in p['dimensions'] if d['dimension']=='D')
assert round(d['score'],2)==33.33 and d['done']==1 and d['passed']==1 and d['unknown']==2
na=deepcopy(base);na['manual_checks']+=[check(c,'example.com','No aplica',evidence='Documented justification') for c in ('D-02','D-03')]
assert calculate(na)['score']==100
import test_probe,json
original_dumps=json.dumps
def http_input(obj,*a,**k):
 if isinstance(obj,dict) and obj.get('urls')==['https://example.com']:obj={**obj,'urls':['http://example.com']}
 return original_dumps(obj,*a,**k)
with patch.object(test_probe.json,'dumps',side_effect=http_input):rows=test_probe.run()
assert next(r for r in rows if r['control']=='T-03')['penalty']==1
assert all(r['status']=='No aplica' for r in rows if r['control'] in ('T-01','T-02'))
web={'domain':'example.com','hosts':['example.com'],'scanned':['example.com'],'ports':[{'host':'example.com','port':'80'}],'results':[{'tool':'HTTPx Toolkit','output':'http://example.com [200]'}],'posture_probe':rows}
p=calculate(web)
assert next(d for d in p['dimensions'] if d['dimension']=='T')['score']==0
assert next(d for d in p['dimensions'] if d['dimension']=='E')['score']==100
class Clock:
 def __init__(self):self.value=0
 def monotonic(self):return self.value
 def sleep(self,n):self.value+=n
clock=Clock();stops=[];calls={'passive':0}
def advancing(component,kind,name,**kw):
 if name=='status':return {'status':str(min(100,int(clock.value/12)))}
 if name=='urls':return {'urls':[str(i) for i in range(int(clock.value/10)+1)]}
 if name=='recordsToScan':
  calls['passive']+=1;return {'recordsToScan':str(max(0,4-calls['passive']))}
 if name=='stop':stops.append(kw)
 return {}
with patch.object(zap,'time',clock):
 events=[];r=zap.wait_for_completion(advancing,'0','http://example.com',emit=events.append)
assert r['status']=='OK' and r['elapsed_seconds']>900 and not stops and r['passive_pending']==0
assert any(e.get('extended') for e in events)
clock=Clock()
def stalled(component,kind,name,**kw):
 if name=='status':return {'status':'42'}
 if name=='urls':return {'urls':['http://example.com/']}
 if name=='recordsToScan':return {'recordsToScan':'0'}
 if name=='stop':stops.append(kw)
 return {}
with patch.object(zap,'time',clock):r=zap.wait_for_completion(stalled,'0','http://example.com')
assert r['status']=='PARCIAL' and 'sin avance' in r['partial_reason'] and r['elapsed_seconds']==900
for code,message,expected in [(403,'Access denied','ERROR'),(404,'No information available for that IP.','SIN RESULTADOS'),(404,'Unknown endpoint','ERROR')]:
 with patch.object(ps,'lookup',side_effect=ps.ProviderHTTPError(code,message)):r=ps.record('Shodan','8.8.8.8','SECRET',True)
 assert r['status']==expected and 'SECRET' not in json.dumps(r)
print('PASS v18: 1/3=33.33; unknown retained; N/A excluded; HTTP TLS=0 without double penalty; ZAP extends past 15min, completes passive queue, detects stall; Shodan 403 vs no result')

# Each origin has an independent initial budget, even during a long inventory run.
clock=Clock()
for origin in ('http://one.example.com','http://two.example.com'):
 origin_start=clock.value
 def per_site(component,kind,name,**kw):
  age=clock.value-origin_start
  if name=='status':return {'status':str(min(100,int(age/12)))}
  if name=='urls':return {'urls':[str(i) for i in range(int(age/10)+1)]}
  if name=='recordsToScan':return {'recordsToScan':'0'}
  return {}
 with patch.object(zap,'time',clock):r=zap.wait_for_completion(per_site,'0',origin)
 assert r['status']=='OK' and r['elapsed_seconds']>=1200
assert clock.value>=2400
# HTTP used only to redirect to verified HTTPS must not be treated as plaintext content.
responses={'count':0};original_response=test_probe.Conn.getresponse
from types import SimpleNamespace
def redirect_first(self):
 responses['count']+=1
 if responses['count']==1:return SimpleNamespace(status=301,read=lambda *a:b'',getheaders=lambda:[('Location','https://example.com/')])
 return original_response(self)
with patch.object(test_probe.json,'dumps',side_effect=http_input),patch.object(test_probe.Conn,'getresponse',redirect_first):rows=test_probe.run()
assert next(r for r in rows if r['control']=='T-03')['penalty']==0
print('PASS: separate budgets for two sites; HTTP-to-HTTPS redirect not penalized as plaintext')
