import unittest
from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path
from llm_client import complete,ModelError
from manual_review import clear_automatic_review,review_prompt
from report_ai import approved_note,fingerprint
from posture import calculate
from test_v20 import V20

class V23(unittest.TestCase):
 def test_only_qwen_and_endpoint(self):
  calls=[]
  def post(url,**kw):
   calls.append((url,kw));return SimpleNamespace(ok=True,json=lambda:{'choices':[{'message':{'content':'conexión correcta'},'finish_reason':'stop'}]})
  c={'provider':'local','url':'http://localhost:1234/v1','id':'qwen-3','api_key':''}
  self.assertEqual(complete(c,[{'role':'user','content':'test'}],post),'conexión correcta')
  self.assertEqual(calls[0][0],'http://localhost:1234/v1/chat/completions')
  for provider in ('claude','openai'):
   with self.assertRaises(ModelError):complete({**c,'provider':provider},[],post)
  with self.assertRaises(ModelError):complete({**c,'id':'other-model'},[],post)
  self.assertEqual(len(calls),1)
 def test_imported_editor_cannot_override_qwen(self):
  d=V20().fixture();o=d['observations'][0]
  d['report_review']={'notes':{o['id']:{'validated':True,'fingerprint':fingerprint(o),'explanation':'obsolete'}}}
  self.assertIsNone(approved_note(d,o))
  d.update(report_model={'provider':'claude','id':'old'},report_ai={'notes':{'old':{}}},narrative={'executive':'old'},reviewer_config_digest='old')
  score=calculate(d)['score'];obs=deepcopy(d['observations'])
  clear_automatic_review(d)
  for k in ('report_review','reviewer_config_digest','report_ai','narrative'):self.assertNotIn(k,d)
  self.assertEqual(calculate(d)['score'],score);self.assertEqual(d['observations'],obs)
 def test_manual_prompt_preserves_evidence_and_score(self):
  d=V20().fixture();before=deepcopy(d);prompt=review_prompt(d)
  self.assertEqual(d,before);self.assertIn(str(calculate(d)['score']),prompt)
  self.assertIn('informe_revisado.docx',prompt);self.assertIn('No ejecutes herramientas',prompt);self.assertIn('pendiente de ejecución',prompt);self.assertIn('conservando las imágenes',prompt)
 def test_ui_and_backend_no_cloud_reviewer(self):
  app=Path('app.py').read_text(encoding='utf-8');backend=Path('backend.py').read_text(encoding='utf-8')
  self.assertNotIn('Revisión automática del informe con Claude',app);self.assertNotIn('st.selectbox("Proveedor"',app)
  self.assertNotIn('from report_review import',backend);self.assertIn('Descargar prompt para Claude',app)
if __name__=='__main__':unittest.main(verbosity=2)
