"""NSE parsing, partial results, local CA ambiguity, vulnerable route confirmation."""
import json,sys,types,io
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch
from nmap_checks import tls_checks
from posture import calculate,checks_for
from intelligence import build_observations
from test_probe import Conn,TLS,CertError
from posture_probe import SCRIPT
xml='<nmaprun><host><ports><port portid="443"><script id="ssl-enum-ciphers" output="TLSv1.1&#10;TLS_RSA_WITH_RC4_128_SHA"><table key="TLSv1.1"/><table key="TLSv1.2"/></script></port></ports></host></nmaprun>'
r={'tool':'Nmap web/TLS · https://example.com · 8.8.8.8','status':'OK','output':xml}
c=tls_checks(r,'https://example.com');assert c['penalty']==.6
r['output']='<nmaprun/>';assert tls_checks(r,'https://example.com')['status']=='No evaluado'
d={'domain':'example.com','hosts':['example.com','www.example.com'],'subdomains':['example.com','www.example.com'],
 'resolved':['example.com','www.example.com'],'scanned':['example.com','www.example.com'],
 'ports':[{'host':h,'ip':'8.8.8.8','port':'443','protocol':'tcp'} for h in ['example.com','www.example.com']],
 'results':[{'tool':'Nmap · '+h+' · 8.8.8.8','status':'OK','output':'','stderr':''} for h in ['example.com','www.example.com']],
 'posture_probe':[{'control':'T-01','asset':'https://example.com','status':'Evaluado','penalty':.6,'evidence':'unable to get local issuer certificate'}]}
d['results'].append({'tool':'HTTPx Toolkit','status':'OK','output':'https://example.com [200]','stderr':''})
assert next(c for c in checks_for(d) if c['control']=='T-01')['status']=='No evaluado'
obs,cov=build_observations(d);assert sum(o['title']=='Servicios TCP accesibles' for o in obs)==1
# Regression based on the real upload: all three resolved hosts are retained;
# missing hosts failed in Nmap DNS, not because of an inventory cap.
path=Path(__file__).parent.parent/'upload/evidencias_postura_externa(4).json'
if path.exists():
 original=json.loads(path.read_text(encoding='utf-8'));assert len(set(original['resolved'])|set(original.get('explicit_ips',[])))==3
 p=calculate(original)
 assert all(c['status']=='No evaluado' for c in p['checks'] if c['control']=='T-01' and 'unable to get local issuer certificate' in c['evidence'])
print('PASS: old TLS/weak cipher, no script unknown, local issuer ambiguity, shared-IP port dedup, uploaded regression')

if path.exists():
 from test_flow import backend_functions
 import shlex
 env=backend_functions();calls=[]
 def fake(name,args,timeout=90,input_text=None):
  calls.append((name,args));out=''
  if name=='HTTPx Toolkit':out='\n'.join('https://'+h+' [200]' for h in original['resolved'])
  elif name.startswith('Nmap · '):
   assert '-n' in args and args[-1] in {ip for values in original['dns_ips'].values() for ip in values}
   out='<nmaprun><host><address addr="'+args[-1]+'"/><ports><port portid="443" protocol="tcp"><state state="open"/><service name="https"/></port></ports></host></nmaprun>'
  return {'tool':name,'status':'OK','exit':0,'output':out,'stderr':'','command':' '.join(shlex.quote(x) for x in args)}
 env['run_tool']=fake;env['save_checkpoint']=lambda d:None;env['capture_web']=lambda *a:dict(id='TEST',url=a[0])
 env['st'].session_state={}
 evaluated=env['evaluate_inventory'](original,types.SimpleNamespace(write=lambda *a:None))
 assert len(evaluated['scanned'])==len(original['resolved'])==3
 assert not any(n.startswith(('Naabu','testssl')) for n,args in calls)
 print('PASS: uploaded inventory evaluated completely by public IP without local Nmap DNS')

from evidence_capture import relink_visuals
old=[{'id':'EXT-002','title':'Certificado','asset':'https://example.com','fact':'issuer'}]
new=[{'id':'EXT-002','title':'DMARC','asset':'example.com','fact':'p=none'}]
visuals=[{'observation_id':'EXT-002','source':'old certificate'}]
relink_visuals(old,new,visuals)
assert visuals[0]['observation_id']=='ARCHIVED-EXT-002'
print('PASS: changed finding ids cannot relink old images to a different condition')

from test_flow import backend_functions
from types import SimpleNamespace
namespace=backend_functions()
namespace['st'].session_state=SimpleNamespace(connection={'host':'kali','port':22,'user':'test','password':'placeholder','fingerprint':'fp'})
namespace['ssh_command']=lambda *a,**k:(0,'','Maximum running time for entire process reached, exiting.')
r=namespace['run_tool']('FFUF · https://example.com',['ffuf'])
assert r['status']=='PARCIAL'
print('PASS: FFUF per-URL max-time is partial, not a completed scan')
