"""Qwen via an LM Studio compatible endpoint. No credentials or response bodies in diagnostic errors."""
import json,requests

class ModelError(RuntimeError):pass

# Per (endpoint, model): structured-output mode the server accepted and loaded context window.
# LM Studio rejects json_object and only admits json_schema/text, so one rejection is remembered.
FORMAT={};CONTEXT={}
LADDER=('json_schema','json_object',None)
MIN_CONTEXT=8192
# Parallel requests share LM Studio's loaded window (measured: three ~2.8k-token prompts overflow 4096 together).
PER_REQUEST=4096
SEED=7;TEMPERATURE=.1

def base_url(config):
    base=config['url'].rstrip('/')
    return base[:-3] if base.endswith('/v1') else base

def check(config):
    if config.get('provider','local')!='local':raise ModelError('Esta versión admite únicamente Qwen mediante LM Studio')
    if 'qwen' not in str(config.get('id','')).lower():raise ModelError('El ID debe identificar un modelo Qwen cargado en LM Studio')
    if not base_url(config).startswith(('http://','https://')):raise ModelError('La URL de LM Studio debe usar HTTP o HTTPS')

def models(config,get=None):
    """Models published by the server. LM Studio's native API adds state and loaded context; plain OpenAI lists do not."""
    get=get or requests.get;base=base_url(config)
    if not base.startswith(('http://','https://')):raise ModelError('La URL de LM Studio debe usar HTTP o HTTPS')
    for path,native in (('/api/v0/models',True),('/v1/models',False)):
        try:response=get(base+path,timeout=(5,15))
        except requests.Timeout:raise ModelError('local: tiempo de respuesta agotado al listar modelos') from None
        except requests.RequestException:raise ModelError('local: fallo de conexión o TLS; comprueba que el servidor de LM Studio está iniciado') from None
        if not response.ok:continue
        try:rows=response.json()['data']
        except (KeyError,TypeError,ValueError):continue
        return [{'id':r.get('id',''),'type':r.get('type','llm'),'state':r.get('state') if native else None,
                 'context':r.get('loaded_context_length') if native else None,'max_context':r.get('max_context_length') if native else None}
                for r in rows if isinstance(r,dict) and r.get('type','llm') not in ('embeddings','embedding')]
    raise ModelError('local: el servidor no publica la lista de modelos')

def diagnose(config,get=None):
    """Confirms the exact ID exists; LM Studio otherwise answers with whatever model is loaded."""
    check(config)
    rows=models(config,get);row=next((r for r in rows if r['id']==config['id']),None)
    if not row:
        ids=[r['id'] for r in rows if 'qwen' in r['id'].lower()]
        raise ModelError('El ID no existe en LM Studio'+('; modelos Qwen disponibles: '+', '.join(ids[:8]) if ids else ''))
    warnings=[]
    if row['state'] and row['state']!='loaded':warnings.append('El modelo no está cargado; LM Studio lo cargará en la primera petición y puede tardar.')
    if row['context']:
        CONTEXT[(base_url(config),config['id'])]=row['context']
        if row['context']<MIN_CONTEXT:warnings.append(f"Ventana de contexto cargada: {row['context']} tokens. Se recomiendan al menos {MIN_CONTEXT}; recarga el modelo en LM Studio con mayor longitud de contexto.")
        elif workers_for(row['context'],4)<4:warnings.append(f"Con {row['context']} tokens se redactan {workers_for(row['context'],4)} hallazgos a la vez; con {4*PER_REQUEST} serían 4.")
    return {**row,'warnings':warnings}

def workers_for(context,requested):
    """Concurrent drafts that fit the shared window; unknown context means one at a time."""
    return max(1,min(requested,context//PER_REQUEST)) if context else 1

def prepare(config,get=None,post=None):
    """Diagnose; if LM Studio still has to load the model (JIT), load it with a short request and read its real context."""
    info=diagnose(config,get)
    if info['state'] and info['state']!='loaded':
        complete(config,[{'role':'system','content':'Responde exactamente con la palabra OK.'},{'role':'user','content':'Carga del modelo'}],post)
        info=diagnose(config,get)
    return info

def estimate(messages):
    # Conservative for Spanish JSON with Qwen tokenizers (about 3 characters per token).
    return sum(len(str(m.get('content',''))) for m in messages)//3+16*len(messages)

def response_format(mode,schema):
    if mode=='json_schema':return {'type':'json_schema','json_schema':{'name':'respuesta','strict':True,'schema':schema or {'type':'object'}}}
    if mode=='json_object':return {'type':'json_object'}

def complete(config,messages,post=None,schema=None,meta=None,share=1):
    # meta, when given, receives what is needed to reproduce the call: served model, decoding settings, usage, requests.
    meta=meta if meta is not None else {}
    meta.update(requested_model=config.get('id'),seed=SEED,temperature=TEMPERATURE,requests=0)
    post=post or requests.post
    check(config)
    provider=config.get('provider','local');base=base_url(config);key=config.get('api_key','');model_key=(base,config['id'])
    structured=schema is not None or any('Devuelve' in m.get('content','') and 'JSON' in m.get('content','') for m in messages if m.get('role')=='system')
    # Without an explicit schema, keep the generic JSON mode; a schema lets LM Studio constrain the grammar.
    modes=list(LADDER if schema is not None else LADDER[1:]) if structured else [None]
    if model_key in FORMAT and FORMAT[model_key] in modes:modes=modes[modes.index(FORMAT[model_key]):]
    context=CONTEXT.get(model_key);needed=estimate(messages)
    if context and share>1:context//=share
    if context and needed+256>context:raise ModelError(f'{provider}: la petición (~{needed} tokens) no cabe en la ventana cargada de {context} tokens; recarga el modelo con mayor contexto')
    headers={'Authorization':'Bearer '+key} if key else {};endpoint='/v1/chat/completions';last=None
    for budget in (2048,4096):
        # Never let output overflow the loaded window: LM Studio would shift context and drop the instructions.
        if context:budget=min(budget,context-needed-64)
        if last is not None and budget<=last:break
        last=budget
        while True:
            payload={'model':config['id'],'messages':messages,'max_tokens':budget,'temperature':TEMPERATURE,'seed':SEED}
            fmt=response_format(modes[0],schema)
            if fmt:payload['response_format']=fmt
            meta['requests']+=1
            try:response=post(base+endpoint,json=payload,headers=headers,timeout=(15,180))
            except requests.Timeout:raise ModelError(provider+': tiempo de respuesta agotado') from None
            except requests.RequestException:raise ModelError(provider+': fallo de conexión o TLS') from None
            if fmt and getattr(response,'status_code',200)==400 and len(modes)>1:
                try:unsupported=str(response.json().get('error',{})).lower()
                except ValueError:unsupported=''
                if any(word in unsupported for word in ('response_format','json_object','json_schema','structured output')):
                    modes.pop(0);FORMAT[model_key]=modes[0];continue
            break
        if not response.ok:
            code=response.status_code
            detail=''
            try:
                error=response.json().get('error',{})
                detail=str(error.get('message','') if isinstance(error,dict) else error)
                from redaction import text
                detail=text(detail)
                if key:detail=detail.replace(key,'[REDACTADO]')
                detail=detail[:320]
            except (ValueError,TypeError,AttributeError):pass
            overflow=code==400 and any(w in detail.lower() for w in ('context length','context size','n_ctx','context window'))
            kind='ventana de contexto insuficiente; recarga el modelo en LM Studio con mayor contexto' if overflow else 'autenticación o permisos' if code in (401,403) else 'cuota o límite de peticiones' if code==429 else 'modelo o petición no admitida' if code in (400,404) else 'servicio no disponible'
            raise ModelError(f'{provider}: HTTP {code}; {kind}'+('; '+detail if detail else ''))
        try:
            obj=response.json()
            choice=obj['choices'][0];content=choice['message'].get('content') or '';truncated=choice.get('finish_reason')=='length'
        except (KeyError,TypeError,ValueError,IndexError):raise ModelError(provider+': formato de respuesta incompatible') from None
        served=obj.get('model') if isinstance(obj,dict) else None
        if isinstance(served,str) and served and served!=config['id'] and not served.startswith(config['id']+':'):raise ModelError(f'{provider}: LM Studio respondió con otro modelo ({served[:80]}); revisa el ID configurado')
        meta.update(served_model=served or None,max_tokens=budget,response_format=modes[0] or 'texto',finish_reason=choice.get('finish_reason'),usage=obj.get('usage') if isinstance(obj.get('usage'),dict) else None,context=context)
        if truncated:continue
        if not content.strip():raise ModelError(provider+': respuesta vacía')
        return content.strip()
    raise ModelError(provider+': respuesta truncada tras ampliar el límite'+(f' (ventana cargada {context} tokens)' if context else ''))

def writer(config,parallel=3,get=None,post=None):
    """Thread-safe drafting callable for report_ai.compose. Loads the model if needed and sizes concurrency to its window."""
    config=dict(config);info=prepare(config,get,post);workers=workers_for(info.get('context'),parallel)
    def write(messages,schema=None,meta=None):
        # Each concurrent request is capped to its share of the window, so together they cannot overflow it.
        return complete(config,messages,post,schema=schema,meta=meta,share=workers)
    write.accepts_schema=write.accepts_meta=True;write.parallel=workers;write.model_id=config.get('id');write.context=info.get('context');write.warnings=info['warnings']
    return write
