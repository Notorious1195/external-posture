import unittest,json
from types import SimpleNamespace
import llm_client
from llm_client import complete,diagnose,models,ModelError
from report_ai import compose,ask,UNSUPPORTED_CONCLUSION,finding_schema,affirmed,validate_prose
from posture import calculate
from test_v20 import V20
C={'provider':'local','url':'http://127.0.0.1:1234','id':'qwen/qwen3-4b-2507'}
def reply(content='{"ok":true}',model=None,finish='stop'):
 body={'choices':[{'message':{'content':content},'finish_reason':finish}]}
 if model:body['model']=model
 return SimpleNamespace(ok=True,status_code=200,json=lambda:body)
def listing(rows):return lambda url,**k:SimpleNamespace(ok=url.endswith('/api/v0/models'),status_code=200,json=lambda:{'data':rows})
ROWS=[{'id':'qwen/qwen3-4b-2507','type':'llm','state':'loaded','loaded_context_length':4096,'max_context_length':262144},
      {'id':'qwen3-14b-instruct','type':'llm','state':'not-loaded','max_context_length':40960},
      {'id':'text-embedding-nomic','type':'embeddings','state':'not-loaded'}]
class V25(unittest.TestCase):
 def setUp(self):llm_client.FORMAT.clear();llm_client.CONTEXT.clear()
 def test_served_model_must_match_requested_id(self):
  # LM Studio answers an unknown ID with whatever model is loaded.
  with self.assertRaisesRegex(ModelError,'otro modelo'):complete({**C,'id':'qwen-inexistente'},[{'role':'user','content':'x'}],lambda u,**k:reply(model='qwen/qwen3-4b-2507'))
  self.assertEqual(complete(C,[{'role':'user','content':'x'}],lambda u,**k:reply('ok',model='qwen/qwen3-4b-2507:2')),'ok')
 def test_lm_studio_rejects_json_object_and_choice_is_remembered(self):
  calls=[]
  def post(url,**kw):
   calls.append(kw['json'].get('response_format',{}).get('type'))
   if calls[-1]=='json_object':return SimpleNamespace(ok=False,status_code=400,json=lambda:{'error':"'response_format.type' must be 'json_schema' or 'text'"})
   return reply()
  m=[{'role':'system','content':'Devuelve solo JSON'},{'role':'user','content':'x'}]
  complete(C,m,post);complete(C,m,post)
  self.assertEqual(calls,['json_object',None,None])
 def test_schema_uses_json_schema(self):
  calls=[];schema=finding_schema(['HAL-1'])
  complete(C,[{'role':'user','content':'x'}],lambda u,**k:calls.append(k['json'])or reply(),schema=schema)
  self.assertEqual(calls[0]['response_format']['type'],'json_schema');self.assertEqual(calls[0]['response_format']['json_schema']['schema'],schema)
  self.assertEqual(schema['properties']['hallazgos']['items']['properties']['id']['enum'],['HAL-1'])
 def test_diagnose_lists_context_and_unknown_id(self):
  info=diagnose(C,listing(ROWS));self.assertEqual(info['context'],4096);self.assertTrue(any('8192' in w for w in info['warnings']))
  self.assertEqual([m['id'] for m in models(C,listing(ROWS))],['qwen/qwen3-4b-2507','qwen3-14b-instruct'])
  with self.assertRaisesRegex(ModelError,'qwen3-14b-instruct'):diagnose({**C,'id':'qwen-otro'},listing(ROWS))
  self.assertTrue(any('no está cargado' in w for w in diagnose({**C,'id':'qwen3-14b-instruct'},listing(ROWS))['warnings']))
 def test_output_budget_capped_by_loaded_context(self):
  diagnose(C,listing(ROWS));calls=[]
  def post(url,**kw):calls.append(kw['json']['max_tokens']);return reply(finish='length')
  with self.assertRaisesRegex(ModelError,'truncada'):complete(C,[{'role':'user','content':'a'*3000}],post)
  self.assertEqual(calls,[2048,4096-1016-64])
  with self.assertRaisesRegex(ModelError,'no cabe'):complete(C,[{'role':'user','content':'a'*13000}],post)
 def test_context_overflow_error_is_named(self):
  post=lambda u,**k:SimpleNamespace(ok=False,status_code=400,json=lambda:{'error':'The number of tokens to keep from the initial prompt is greater than the context length (n_keep: 5011>= n_ctx: 4096).'})
  with self.assertRaisesRegex(ModelError,'ventana de contexto insuficiente'):complete(C,[{'role':'user','content':'x'}],post)
 def test_retry_carries_rejection_reason_and_keeps_payload_last(self):
  d=V20().fixture();p=calculate(d);seen=[];good=V20().model([])
  def model(messages,schema=None):
   seen.append((messages,schema))
   if len(seen)==1:return json.dumps({'hallazgos':[]})
   return good(messages)
  model.accepts_schema=True
  compose(d,model,SimpleNamespace(write=lambda *a:None))
  self.assertIn('rechazada',seen[1][0][0]['content']);json.loads(seen[1][0][-1]['content'])
  self.assertTrue(all(s is not None for _,s in seen));self.assertEqual(p,calculate(d));self.assertEqual(d['report_ai']['status'],'OK')
 def test_executive_conclusion_check_is_clause_bounded(self):
  self.assertIsNone(UNSUPPORTED_CONCLUSION.search('Se observaron condiciones confirmadas de riesgo bajo. Un atacante podría intentar el compromiso de cuentas.'))
  for bad in ('Existe explotación confirmada del servidor.','Se ha confirmado la explotación del portal.','El compromiso quedó confirmado.','Seguridad garantizada.'):
   self.assertTrue(affirmed(UNSUPPORTED_CONCLUSION.pattern,bad),bad)
  for fine in ('La ausencia de CSP no implica explotación confirmada.','No se ha confirmado la explotación del portal.','Sin compromiso confirmado, se requiere verificar.'):
   self.assertFalse(affirmed(UNSUPPORTED_CONCLUSION.pattern,fine),fine)
 def test_negated_claim_is_not_rejected(self):
  item={'fact':'Cabecera CSP ausente','status':'Indicio'}
  self.assertTrue(validate_prose('La respuesta no incluye la cabecera CSP. La ausencia de esta política no implica explotación confirmada, pero reduce la protección.',item))
  with self.assertRaisesRegex(ValueError,'Indicio'):validate_prose('La ausencia de CSP deja la vulnerabilidad confirmada en el portal de la empresa.',item)
 def test_plain_writer_without_schema_still_works(self):
  calls=[];self.assertEqual(ask(lambda m:calls.append(m) or 'x',[{'role':'system','content':'s'},{'role':'user','content':'u'}],{'type':'object'}),'x')
if __name__=='__main__':unittest.main(verbosity=2)
