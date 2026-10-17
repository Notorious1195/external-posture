import unittest,json
from types import SimpleNamespace
from copy import deepcopy
from pathlib import Path
from llm_client import complete
from report_ai import parse,compact_context,compose
from report_context import packet
from posture import calculate
from test_v20 import V20
class V24(unittest.TestCase):
 def test_structured_request_truncation_and_budget(self):
  calls=[]
  def post(url,**kw):
   calls.append(kw['json'].copy());return SimpleNamespace(ok=True,status_code=200,json=lambda:{'choices':[{'message':{'content':'{"ok":true}'},'finish_reason':'length' if len(calls)==1 else 'stop'}]})
  complete({'url':'http://localhost:1234','id':'qwen-3'},[{'role':'system','content':'Devuelve solo JSON'}],post)
  self.assertEqual([x['max_tokens'] for x in calls],[2048,4096]);self.assertEqual(calls[0]['response_format'],{'type':'json_object'})
 def test_unsupported_json_mode_fallback(self):
  calls=[]
  def post(url,**kw):
   calls.append(kw['json'].copy())
   if len(calls)==1:return SimpleNamespace(ok=False,status_code=400,json=lambda:{'error':{'message':'response_format json_object unsupported'}})
   return SimpleNamespace(ok=True,status_code=200,json=lambda:{'choices':[{'message':{'content':'{"ok":true}'},'finish_reason':'stop'}]})
  complete({'url':'http://localhost:1234','id':'qwen-3'},[{'role':'system','content':'Devuelve JSON'}],post)
  self.assertNotIn('response_format',calls[1])
 def test_parse_reasoning_no_repair(self):
  self.assertEqual(parse('<think>razonamiento</think>\n```json\n{"ok":true}\n```'),{'ok':True})
  with self.assertRaises((ValueError,json.JSONDecodeError)):parse('{"hallazgos":[')
 def test_single_finding_and_score_immutable(self):
  d=V20().fixture();p=calculate(d);calls=[]
  compose(d,V20().model(calls),SimpleNamespace(write=lambda *a:None))
  self.assertTrue(all(len(json.loads(c[-1]['content'])['detail'])==1 for c in calls if 'detail' in json.loads(c[-1]['content'])))
  self.assertEqual(p,calculate(d));self.assertEqual(d['report_ai']['status'],'OK')
  ctx=compact_context(packet(d),d['observations'][:1]);self.assertIn('methodology',ctx);self.assertEqual(ctx['score'],p['score'])
 def test_requested_ui_removals(self):
  s=Path('app.py').read_text(encoding='utf-8');self.assertNotIn('Token de LM Studio',s);self.assertNotIn("st.subheader('IPs públicas candidatas",s);self.assertNotIn('st.checkbox("Ejecutar ZAP',s)
  self.assertIn('zap_enabled=True',Path('web_stage.py').read_text(encoding='utf-8'))
if __name__=='__main__':unittest.main(verbosity=2)
