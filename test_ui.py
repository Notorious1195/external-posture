"""Offline rendering smoke test; does not substitute Streamlit browser validation."""
import runpy,sys,types
from pathlib import Path
try:import requests
except ImportError:
 m=types.ModuleType('requests');m.RequestException=Exception;sys.modules['requests']=m
class State(dict):
 __getattr__=dict.__getitem__
 __setattr__=dict.__setitem__
class Surface:
 def __enter__(self):return self
 def __exit__(self,*args):return False
 def __getattr__(self,name):
  if name=='button' or name=='form_submit_button':return lambda *a,**k:False
  if name=='file_uploader':return lambda *a,**k:None
  if name in ('text_input','text_area'):return lambda *a,**k:k.get('value','')
  if name=='checkbox':return lambda *a,**k:k.get('value',False)
  if name=='multiselect':return lambda *a,**k:k.get('default',[])
  if name=='selectbox':return lambda label,options,**k:list(options)[0] if options else None
  if name=='number_input':return lambda *a,**k:a[3] if len(a)>3 else 22
  if name=='columns':return lambda specs,**k:[Surface() for _ in range(specs if isinstance(specs,int) else len(specs))]
  if name=='tabs':return lambda labels:[Surface() for _ in labels]
  if name in ('expander','form','status'):return lambda *a,**k:Surface()
  return lambda *a,**k:None
surface=Surface();st=types.ModuleType('streamlit');st.__getattr__=surface.__getattr__;st.sidebar=Surface();sys.modules['streamlit']=st
backend=types.ModuleType('backend')
for name in ('domain_ok','probe_host','run_tool','qwen','recognize','evaluate_inventory','generate_narrative','save_checkpoint'):
 setattr(backend,name,lambda *a,**k:None)
sys.modules['backend']=backend
from intelligence import build_observations
fixture={'domain':'example.com','date':'2026-09-30','hosts':['example.com'],'subdomains':['example.com'],
 'resolved':['example.com'],'explicit_ips':[],'dns_ips':{'example.com':['8.8.8.8']},'ports':[],
 'scanned':[],'results':[],'historical_count':0,'visual_evidence':[],'visual_errors':[]}
fixture['observations'],fixture['coverage']=build_observations(fixture)
for page in range(12):
 st.session_state=State(page=page,scan=fixture,scope={'domain':'example.com','ips':[]},model_ok=False)
 runpy.run_path(str(Path(__file__).with_name('app.py')))
print('PASS: 12 screen branches render with offline UI substitute; DOCX download branch executes')
