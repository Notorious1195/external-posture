import json,unittest
from copy import deepcopy
from pathlib import Path
from access_policy import normalize,unavailable,REMOTE_PROBE
from nmap_checks import tls_checks
from posture import calculate,explanation,check
from intelligence import build_observations
class V21(unittest.TestCase):
 def test_xml_compressor_not_cipher(self):
  xml='<nmaprun><script id="ssl-enum-ciphers" output="compressors: NULL"><table key="TLSv1.2"><table key="ciphers"><table><elem key="name">TLS_RSA_WITH_AES_128_GCM_SHA256</elem><elem key="strength">A</elem></table></table><table key="compressors"><elem>NULL</elem></table></table></script></nmaprun>'
  r={'tool':'Nmap TLS','status':'OK','output':xml};self.assertEqual(tls_checks(r,'https://example.com')['penalty'],0)
  r['output']=xml.replace('TLS_RSA_WITH_AES_128_GCM_SHA256','TLS_RSA_WITH_NULL_SHA');self.assertEqual(tls_checks(r,'https://example.com')['penalty'],.6)
 def test_blocked_no_zap_findings_or_credit(self):
  d={'domain':'example.com','hosts':['example.com'],'scanned':['example.com'],'ports':[],'resolved':['example.com'],'results':[{'tool':'HTTPx Toolkit','status':'OK','output':'https://example.com [403]'}],'web_access':[{'url':'https://example.com','http_status':403}],'zap_reports':[{'url':'https://example.com','status':'OK','crawler_complete':True,'passive_pending':0,'alerts':[{'pluginId':'10202','url':'https://example.com/','risk':'High','confidence':'High','name':'CSRF','evidence':'unlock'}]}]}
  normalize(d);obs,_=build_observations(d);self.assertFalse(any(o.get('zap_rule') for o in obs))
  p=calculate(d);self.assertEqual(p['category'],'No concluyente');self.assertTrue(all(c['status']=='No evaluado' for c in p['checks'] if c['dimension'] in ('V','W')));self.assertNotIn('csrf',explanation(d,p).lower())
 def test_tcpwrapped_unidentified_service_unknown(self):
  d={'domain':'example.com','hosts':['example.com'],'scanned':['example.com'],'ports':[{'host':'example.com','port':'8888','service':'tcpwrapped'}]};p=calculate(d)
  self.assertEqual(next(c for c in p['checks'] if c['control']=='E-01')['status'],'No evaluado')
 def test_supplied_checkpoint(self):
  path=Path('../upload/evidencias_postura_externa(20261001-013040).json')
  if not path.exists():self.skipTest('Checkpoint no incluido en el ZIP')
  d=json.loads(path.read_text(encoding='utf-8'));normalize(d)
  self.assertTrue(all(c['penalty']==0 for c in d['nmap_tls_checks']))
  p=calculate(d);self.assertEqual(p['category'],'No concluyente')
  obs,_=build_observations(d);self.assertFalse(any(o.get('zap_rule') for o in obs))
if __name__=='__main__':unittest.main(verbosity=2)
