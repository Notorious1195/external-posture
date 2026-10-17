"""Parallel drafting, provenance records, shared context window and reader-facing number formats."""
import json,threading
from io import BytesIO
from types import SimpleNamespace
from docx import Document
import llm_client
from llm_client import complete,workers_for,writer
from report_ai import compose,incomplete_tools
from posture import es_num,sentence_case,calculate
from docx_report import report_docx,SHOWN_URLS
import test_v20

def fixture():return test_v20.V20().fixture()

def mock(parallel=1,fail=()):
    lock=threading.Lock();calls=[]
    def model(messages,schema=None,meta=None):
        payload=json.loads(messages[-1]['content'])
        with lock:calls.append(payload)
        if meta is not None:meta.update(served_model='qwen-test',seed=7,temperature=.1,usage={'total_tokens':100})
        if 'detail' not in payload:
            return json.dumps({'interpretacion':'La organización debe priorizar las condiciones observadas, coordinar las correcciones con los responsables y contrastar cada mejora desde un punto externo autorizado.','referencias':[payload['findings'][0]['id']]})
        x=payload['detail'][0]
        if x['id'] in fail:return json.dumps({'hallazgos':[]})
        return json.dumps({'hallazgos':[{'id':x['id'],'explicacion':'La condición descrita requiere atención de los responsables. La comprobación documentada permite revisar la configuración y su relevancia para el negocio.','recomendacion':'Aplicar la corrección documentada con el responsable de la aplicación y repetir la comprobación específica desde un punto externo autorizado.','referencias':[x['id']]}]})
    model.accepts_schema=model.accepts_meta=True;model.parallel=parallel;model.model_id='qwen-test'
    return model,calls

def test_parallel_matches_sequential_and_keeps_score():
    a,b=fixture(),fixture();score=calculate(a)['score']
    compose(a,mock(1)[0],SimpleNamespace(write=lambda *x:None));compose(b,mock(3)[0],SimpleNamespace(write=lambda *x:None))
    strip=lambda d:{k:{f:v for f,v in n.items() if f!='provenance'} for k,n in d['report_ai']['notes'].items()}
    assert strip(a)==strip(b) and b['report_ai']['run']['parallel']==3 and calculate(b)['score']==score

def test_provenance_per_attempt_and_fallback():
    d=fixture();target=d['observations'][0]['id']
    compose(d,mock(2,fail={target})[0],SimpleNamespace(write=lambda *x:None))
    ai=d['report_ai'];record=ai['fallbacks'][target]
    assert record['result']=='catálogo' and len(record['attempts'])==2
    assert all(a['outcome']=='rechazada' and a['prompt_sha256'] and a['seed']==7 for a in record['attempts'])
    assert record['attempts'][0]['prompt_sha256']!=record['attempts'][1]['prompt_sha256'],'retry prompt carries the rejection reason'
    note=next(n for k,n in ai['notes'].items());p=note['provenance']
    assert p['evidence_sha256'] and p['attempts'][-1]['outcome']=='aceptada' and p['attempts'][-1]['served_model']=='qwen-test'
    assert ai['run']['model']=='qwen-test' and ai['executive_provenance']['result']=='validada'
    assert [e['batch'] for e in ai['errors']]==sorted(e['batch'] for e in ai['errors'] if isinstance(e['batch'],int))+[e['batch'] for e in ai['errors'] if not isinstance(e['batch'],int)]

def test_workers_follow_shared_window():
    assert [workers_for(c,3) for c in (None,4096,8192,16384,32768)]==[1,1,2,3,3]

def test_concurrent_requests_capped_to_their_share():
    llm_client.FORMAT.clear();llm_client.CONTEXT.clear();budgets=[]
    rows=[{'id':'qwen-x','type':'llm','state':'loaded','loaded_context_length':8192}]
    get=lambda url,**k:SimpleNamespace(ok=url.endswith('/api/v0/models'),status_code=200,json=lambda:{'data':rows})
    def post(url,**kw):
        budgets.append(kw['json']['max_tokens'])
        return SimpleNamespace(ok=True,status_code=200,json=lambda:{'model':'qwen-x','choices':[{'message':{'content':'ok'},'finish_reason':'stop'}]})
    w=writer({'provider':'local','url':'http://127.0.0.1:1234','id':'qwen-x'},3,get,post)
    assert (w.parallel,w.context)==(2,8192)
    meta={};w([{'role':'user','content':'a'*3000}],meta=meta)
    assert budgets[-1]<=4096-1016-64+1 and meta['served_model']=='qwen-x' and meta['seed']==7

def test_writer_loads_jit_model_before_reading_context():
    llm_client.FORMAT.clear();llm_client.CONTEXT.clear();state={'loaded':False}
    def get(url,**k):
        row={'id':'qwen-x','type':'llm','state':'loaded' if state['loaded'] else 'not-loaded',**({'loaded_context_length':16384} if state['loaded'] else {})}
        return SimpleNamespace(ok=url.endswith('/api/v0/models'),status_code=200,json=lambda:{'data':[row]})
    def post(url,**kw):
        state['loaded']=True
        return SimpleNamespace(ok=True,status_code=200,json=lambda:{'model':'qwen-x','choices':[{'message':{'content':'OK'},'finish_reason':'stop'}]})
    w=writer({'provider':'local','url':'http://127.0.0.1:1234','id':'qwen-x'},4,get,post)
    assert (w.context,w.parallel)==(16384,4)

def test_spanish_numbers_and_acronyms():
    assert (es_num(59.15),es_num(55.5),es_num(3.3333,2))==('59,15','55,5','3,33')
    assert sentence_case('Política DMARC del dominio evaluado')=='política DMARC del dominio evaluado'

def test_long_url_lists_go_to_annex_and_tools_listed():
    d=fixture();o=d['observations'][0];o['affected_urls']=[f'http://example.com/p{i}' for i in range(SHOWN_URLS+3)]
    d['results'].append({'tool':'FFUF · http://example.com','status':'PARCIAL','output':''})
    compose(d,None,SimpleNamespace(write=lambda *x:None))
    assert 'FFUF · http://example.com (PARCIAL)' in incomplete_tools(d)
    text='\n'.join(p.text for p in Document(BytesIO(report_docx(d))).paragraphs)
    assert f'… y 3 más (anexo «Ubicaciones afectadas por hallazgo», {o["id"]})' in text
    assert 'Ubicaciones afectadas por hallazgo' in text and f'http://example.com/p{SHOWN_URLS+2}' in text
    assert text.count('Un bloqueo de la herramienta o una respuesta incompleta no acredita corrección')==1
