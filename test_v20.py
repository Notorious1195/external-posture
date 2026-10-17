"""Version 20: automatic workflow, faithful narratives, stable identities and intelligence."""
import io,json,unittest,hashlib
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
from finding_model import consolidate,classify,human_description
from intelligence import build_observations
from posture import calculate,check
from report_ai import compose,approved_note,validate_prose
from report_workflow import ensure
from report_context import signature
from docx_report import report_docx
from docx import Document
from redaction import clean,text,utf8
from llm_client import complete,ModelError

class V20(unittest.TestCase):
 def fixture(self):
  d={'domain':'example.com','organization':'Empresa de prueba','project_name':'Evaluación externa','date':'2026-10-01','hosts':['example.com'],'scanned':['example.com'],'ports':[],'subdomains':['example.com'],'resolved':['example.com'],'explicit_ips':[],'dns_ips':{},'visual_evidence':[],'historical_count':0,'results':[{'tool':'HTTPx Toolkit','status':'OK','output':'http://example.com [200]'}], 'posture_probe':[check('W-01','http://example.com','Evaluado',.25,'Header absent'),check('T-03','http://example.com','Evaluado',1,'HTTP content, no HTTPS redirect')]}
  d['observations'],d['coverage']=build_observations(d);return d
 def test_stable_ids_and_correct_risk(self):
  d=self.fixture();old={o['condition'] if o.get('condition') else o['title']:o['id'] for o in d['observations']}
  d['posture_probe'].reverse();obs,_=build_observations(d)
  self.assertEqual(old,{o['condition'] if o.get('condition') else o['title']:o['id'] for o in obs})
  waf={'id':'tmp','title':'Protección web detectada','status':'Indicio','asset':'https://example.com','fact':'WAF indication','implication':'context','recommendation':'context','evidence':[]}
  self.assertEqual(classify(waf)['risk'],'Informativo')
  for control in ('W-02','D-01'):
   row={**waf,'title':'deficiency','status':'Confirmado','control':control,'control_penalty':.25};self.assertEqual(classify(row)['risk'],'Bajo')
  row={**waf,'title':'deficiency','status':'Confirmado','control':'D-02','control_penalty':1};self.assertEqual(classify(row)['risk'],'Medio')
 def test_catalog_and_repeated_alerts(self):
  d=self.fixture();a={'pluginId':'10031','risk':'Informational','confidence':'Low','url':'http://example.com/a','name':'User Controllable HTML Element Attribute (Potential XSS)','description':'passive','solution':'Validate all input','param':'NewsAd'}
  d['zap_reports']=[{'url':'http://example.com','alerts':[a]*20}]
  obs,_=build_observations(d);x=[o for o in obs if o.get('zap_rule')=='10031'];self.assertEqual(len(x),1);self.assertIn('XSS',x[0]['title']);self.assertNotIn('nube',x[0]['title']);self.assertEqual(x[0]['risk'],'Informativo');self.assertIn('NewsAd',x[0]['triage']['prioritize']);self.assertNotIn('Validate',x[0]['recommendation'])
 def model(self,calls,fail_first=False):
  def model(messages):
   calls.append(messages);payload=json.loads(messages[-1]['content'])
   if fail_first and len(calls)==1:raise ModelError('local: tiempo de respuesta agotado')
   if 'detail' not in payload:return json.dumps({'interpretacion':'La organización debe priorizar las condiciones observadas, coordinar las correcciones con los responsables y contrastar cada mejora desde un punto externo autorizado.','referencias':[payload['findings'][0]['id']]})
   self.assertIn('Empresa de prueba',payload['context']['organization']);self.assertIn('dimensions',payload['context']);self.assertIn('public_intelligence',payload['context'])
   return json.dumps({'hallazgos':[{'id':x['id'],'explicacion':'La condición descrita requiere atención de los responsables. La comprobación documentada permite revisar la configuración y determinar su relevancia para las operaciones del negocio.','recomendacion':'Aplicar la corrección documentada con el responsable de la aplicación y repetir la comprobación específica desde un punto externo autorizado.','referencias':[x['id']]} for x in payload['detail']]})
  return model
 def test_automatic_context_and_cache(self):
  d=self.fixture();score=calculate(d)['score'];calls=[];progress=SimpleNamespace(write=lambda *a:None)
  def prepare(data,p):compose(data,self.model(calls,True),p)
  self.assertTrue(ensure(d,prepare,progress));self.assertEqual(calculate(d)['score'],score);self.assertTrue(d['report_preparation']['complete'])
  self.assertEqual(d['report_ai']['status'],'OK');self.assertTrue(d['report_ai']['errors']);self.assertIn('Empresa de prueba',d['narrative']['executive']);self.assertIn('La nota se reduce',d['narrative']['executive'])
  before=len(calls);self.assertFalse(ensure(d,prepare,progress));self.assertEqual(len(calls),before)
  o=d['observations'][0];self.assertIsNotNone(approved_note(d,o));o['fact']+=' changed';self.assertIsNone(approved_note(d,o));self.assertTrue(ensure(d,prepare,progress))
 def test_reject_contradiction_and_redact_docx(self):
  d=self.fixture();o=next(o for o in d['observations'] if o.get('control')=='W-01')
  with self.assertRaises(ValueError):validate_prose('Se detecta X-Frame-Options y el control se encuentra implementado correctamente.',o)
  with self.assertRaises(ValueError):validate_prose('La vulnerabilidad CVE-2099-12345 permite ejecución de código en la aplicación.',o)
  d['posture_probe'][0]['evidence']='{"headers":{"set-cookie":"ASP.NET_SessionId=SECRETSESSION; HttpOnly"}}'
  d['observations'],d['coverage']=build_observations(d);compose(d,None,SimpleNamespace(write=lambda *a:None))
  doc=Document(io.BytesIO(report_docx(d)));body='\n'.join(p.text for p in doc.paragraphs)
  self.assertNotIn('SECRETSESSION',body);self.assertNotIn('Estado de la observación',body);self.assertIn('Descripción y relevancia',body);self.assertIn('Empresa de prueba',body)
 def test_provider_contracts_and_cves(self):
  from intel_context import extract_cves
  self.assertEqual(extract_cves({'vulns':{'CVE-2014-4078':{}}}),{'CVE-2014-4078'})
  for provider in ('local',):
   calls=[]
   def post(url,**kw):
    calls.append((url,kw));return SimpleNamespace(ok=True,json=lambda:{'content':[{'type':'text','text':'correcto'}],'stop_reason':'end_turn'} if provider=='claude' else {'choices':[{'message':{'content':'correcto'},'finish_reason':'stop'}]})
   self.assertEqual(complete({'provider':provider,'url':'https://example.test','id':'qwen-test','api_key':'SECRET'},[{'role':'user','content':'hello'}],post),'correcto')
   self.assertTrue(calls[0][0].endswith('/v1/messages' if provider=='claude' else '/v1/chat/completions'))
  self.assertEqual(utf8('anÃ¡lisis'),'análisis');self.assertNotIn('SECRET',text('Set-Cookie: ASP.NET_SessionId=SECRET; HttpOnly'))
 def test_shodan_kev_epss(self):
  import public_sources as ps
  d=self.fixture();calls=[]
  def record(provider,target,key='',is_ip=False):
   calls.append((provider,target));return {'provider':provider,'target':target,'status':'OK','queried_at_utc':'2026-10-01','data':{'vulns':['CVE-2014-4078']} if provider=='Shodan' else {'data':[{'cve':target,'epss':'.1'}]}}
  with patch.object(ps,'record',side_effect=record),patch.object(ps.time,'sleep',lambda *a:None):
   d['explicit_ips']=['8.8.8.8'];ps.enrich(d,{'enabled':['Shodan','EPSS'],'keys':{}},SimpleNamespace(write=lambda *a:None))
  c=d['public_intelligence']['correlations'][0];self.assertEqual(c['cve'],'CVE-2014-4078');self.assertIn('8.8.8.8',c['assets']);self.assertIn(('EPSS','CVE-2014-4078'),calls)
if __name__=='__main__':unittest.main(verbosity=2)
