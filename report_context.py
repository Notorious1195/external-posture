"""Immutable score and business narrative context for every report request."""
import json,hashlib
from posture import calculate
from finding_model import human_description
from intel_context import context as public_context
from redaction import clean

def signature(data):
    value={'writer_version':'25.0','domain':data['domain'],'organization':data.get('organization'),'project_name':data.get('project_name'),'date':data.get('date'),
           'observations':[{k:o.get(k) for k in ('id','title','fact','status','risk','affected_urls','recommendation')} for o in data.get('observations',[])],
           'checks':calculate(data)['checks'],'intel':public_context(data),'report_model':data.get('report_model'),'config_digest':data.get('report_config_digest'),'capture_available':data.get('capture_connection_available')}
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def packet(data):
    p=calculate(data);items=data.get('observations',[])
    return clean({'purpose':'Evaluar postura externa mediante reconocimiento y ciberinteligencia pública; sin visibilidad interna.',
      'organization':data.get('organization') or data['domain'],'project':data.get('project_name') or 'Evaluación de postura externa','domain':data['domain'],'date':data.get('date'),
      'methodology':p['methodology'],'score':p['score'],'category':p['category'],'coverage':p['coverage'],'interval':p['interval'],
      'dimensions':[{k:d[k] for k in ('dimension','name','score','weight','done','planned','passed','unknown')} for d in p['dimensions']],
      'findings':[{'id':o['id'],'title':o['title'],'risk':o['risk'],'state':o['status'],'summary':human_description(o)[0][:450]} for o in items],
      'public_intelligence':public_context(data),'limits':p['scope']})

def priorities(data):
    rank={'Crítico':0,'Alto':1,'Medio':2,'Bajo':3,'Informativo':4}
    return sorted((o for o in data.get('observations',[]) if o['risk']!='Informativo'),key=lambda o:(rank.get(o['risk'],4),o['status']!='Confirmado',o['id']))[:5]

def executive(data):
    from posture import explanation
    organization=data.get('organization') or data['domain']
    return f"Se evaluó la postura externa de {organization} mediante reconocimiento y ciberinteligencia pública sobre {data['domain']}. "+explanation(data)
