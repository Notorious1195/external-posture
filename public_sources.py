"""Public enrichment only. Credentials stay in session/environment, never in records."""
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
import requests

ROOT = Path(__file__).resolve().parent
PROVIDERS = ['Shodan', 'Censys', 'URLhaus', 'ThreatFox', 'VirusTotal', 'DNSDumpster', 'RDAP', 'EPSS']
ENV_KEYS = {'Shodan':'SHODAN_API_KEY','Censys':'CENSYS_API_TOKEN','URLhaus':'ABUSECH_AUTH_KEY',
            'DNSDumpster':'DNSDUMPSTER_API_KEY','ThreatFox':'ABUSECH_AUTH_KEY','VirusTotal':'VIRUSTOTAL_API_KEY'}

def timestamp():
    return datetime.now(timezone.utc).isoformat()

class ProviderHTTPError(ValueError):
    def __init__(self,status,message):
        self.status=status;self.message=message
        super().__init__(f'HTTP {status}: {message}')

def request_json(method, url, **kwargs):
    """No response body/URL in error messages: URLs can carry keys."""
    try:
        with requests.request(method, url, timeout=(10,35), stream=True, **kwargs) as response:
            if not response.ok:
                retry = response.headers.get('Retry-After','')
                detail=''
                # Bounded body, only the error field; never log credential-bearing URL.
                chunks=[];size=0
                for chunk in response.iter_content(1024):
                    size+=len(chunk)
                    if size>8192:break
                    chunks.append(chunk)
                try:
                    payload=json.loads(b''.join(chunks));detail=payload.get('error','') if isinstance(payload,dict) else ''
                except (ValueError,TypeError):pass
                detail=str(detail)[:400]
                secrets=list(kwargs.get('params',{}).values())+list(kwargs.get('headers',{}).values())
                for secret in secrets:
                    if isinstance(secret,str) and secret:detail=detail.replace(secret,'[REDACTADO]')
                if response.status_code in (401,403):
                    detail='Consulta rechazada; revisar credencial, permisos y plan. '+detail
                raise ProviderHTTPError(response.status_code,detail+(f'; Retry-After: {retry}' if retry else ''))
            chunks=[]; size=0
            for chunk in response.iter_content(65536):
                size+=len(chunk)
                if size>8_000_000: raise ValueError('Respuesta supera 8 MB; no se conserva una salida truncada')
                chunks.append(chunk)
            return json.loads(b''.join(chunks))
    except requests.RequestException:
        raise ValueError('Fallo de conexión/timeout con el proveedor') from None

def sanitize(obj, keys):
    """Remove exact configured secrets even if an upstream service echoes one."""
    raw=json.dumps(obj,ensure_ascii=False)
    for key in keys:
        if key: raw=raw.replace(key,'[REDACTADO]')
    return json.loads(raw)

def lookup(provider, target, key='', is_ip=False):
    q=quote(target,safe='')
    if provider in ENV_KEYS and not key: raise ValueError('Falta credencial')
    if provider=='DNSDumpster':
        if is_ip: raise ValueError('DNSDumpster requiere un dominio para reconocimiento')
        if not re.fullmatch(r'[A-Za-z0-9.-]+',target): raise ValueError('Dominio inválido')
        return request_json('GET','https://api.dnsdumpster.com/domain/'+q,headers={'X-API-Key':key},allow_redirects=False)
    if provider=='Shodan':
        if not is_ip: raise ValueError('Shodan requiere IP')
        return request_json('GET','https://api.shodan.io/shodan/host/'+q,params={'key':key})
    if provider=='Censys':
        if not is_ip: raise ValueError('Censys requiere IP')
        return request_json('GET','https://api.platform.censys.io/v3/global/asset/host/'+q,
                            headers={'Authorization':'Bearer '+key})
    if provider=='URLhaus':
        return request_json('POST','https://urlhaus-api.abuse.ch/v1/host/',data={'host':target},headers={'Auth-Key':key})
    if provider=='ThreatFox':
        return request_json('POST','https://threatfox-api.abuse.ch/api/v1/',
            json={'query':'search_ioc','search_term':target,'exact_match':True},headers={'Auth-Key':key})
    if provider=='VirusTotal':
        collection='ip_addresses' if is_ip else 'domains'
        return request_json('GET','https://www.virustotal.com/api/v3/'+collection+'/'+q,headers={'x-apikey':key})
    if provider=='RDAP':
        from domain_policy import registrable_domain
        return request_json('GET','https://rdap.org/'+('ip/'+q if is_ip else 'domain/'+registrable_domain(target)))
    if provider=='EPSS':
        return request_json('GET','https://api.first.org/data/v1/epss',params={'cve':target})
    raise ValueError('Proveedor desconocido')

def record(provider,target,key='',is_ip=False):
    r={'provider':provider,'target':target,'queried_at_utc':timestamp(),'status':'ERROR','data':None}
    try:
        r['data']=sanitize(lookup(provider,target,key,is_ip),[key]); r['status']='OK'
        if provider in ('ThreatFox','URLhaus'):
            status=r['data'].get('query_status')
            if status not in ('ok','no_result','no_results','no_results_found'):
                r['status']='ERROR'; r['error']='Respuesta del proveedor: '+str(status)
    except ProviderHTTPError as exc:
        r['http_status']=exc.status
        if provider=='Shodan' and exc.status==404 and 'no information available' in exc.message.lower():
            r['status']='SIN RESULTADOS';r['data']={'query_status':'no_result','note':'El proveedor no tiene información para esta IP; no implica ausencia de exposición.'}
        else:
            r['error']=str(exc);r['error_kind']='AUTORIZACION' if exc.status in (401,403) else 'CUOTA' if exc.status==429 else 'HTTP'
    except (ValueError,TypeError,KeyError) as exc: r['error']=str(exc)
    return r

def passive_names(domain):
    """Historical CT candidates, never proof of live asset or ownership."""
    records=None
    for attempt in range(2):
        try:
            records=request_json('GET','https://crt.sh/',params={'q':'%.'+domain,'output':'json'});break
        except ValueError:
            if attempt==0:time.sleep(1)
    if records is None: raise ValueError('CT crt.sh no disponible tras dos intentos; continúan otras fuentes. No prueba ausencia de subdominios.')
    if not isinstance(records,list): raise ValueError('Formato CT inesperado')
    names=set()
    for row in records:
        for name in row.get('name_value','').lower().splitlines():
            name=name.removeprefix('*.').rstrip('.')
            if re.fullmatch(r'[a-z0-9.-]+',name) and (name==domain or name.endswith('.'+domain)): names.add(name)
    return sorted(names)

def kev_catalog():
    return json.loads((ROOT/'data/known_exploited_vulnerabilities.json').read_text(encoding='utf-8'))

def refresh_kev():
    obj=request_json('GET','https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json')
    if not isinstance(obj.get('vulnerabilities'),list) or obj.get('count')!=len(obj['vulnerabilities']):
        raise ValueError('Catálogo KEV inválido')
    target=ROOT/'data/known_exploited_vulnerabilities.json'
    temp=target.with_suffix('.tmp'); temp.write_text(json.dumps(obj,ensure_ascii=False),encoding='utf-8');temp.replace(target)
    return obj

def enrich(data,config,progress):
    names=sorted(set(data.get('resolved',[])))
    ips=set(data.get('explicit_ips',[]))
    for values in data.get('dns_ips',{}).values():
        for ip in values:
            try:
                if ipaddress.ip_address(ip).is_global: ips.add(ip)
            except ValueError: pass
    targets=names+sorted(ips)
    selected=config.get('enabled',[]); keys=config.get('keys',{})
    records=[]
    for provider in selected:
        if provider=='EPSS': continue
        if provider=='DNSDumpster' and data.get('dnsdumpster'):
            records.append({'provider':provider,'target':data['domain'],'status':'OK','data':data['dnsdumpster'],'queried_at_utc':timestamp(),'error':''});continue
        items=[data['domain']] if provider=='DNSDumpster' else sorted(ips) if provider in ('Shodan','Censys') else ([data['domain']]+sorted(ips) if provider=='RDAP' else targets)
        for index,target in enumerate(items):
            progress.write(f'{provider}: {index+1}/{len(items)} · {target}')
            if provider in ('URLhaus','ThreatFox') and config.get('abuse_via_kali',True):
                from backend import run_tool
                r=record_from_kali(provider,target,keys.get(provider,''),run_tool)
            else:r=record(provider,target,keys.get(provider,''),target in ips)
            records.append(r)
            if provider=='VirusTotal': time.sleep(15.5)
            else: time.sleep(.25)
            if r['status']=='ERROR' and any(code in r.get('error','') for code in ('HTTP 401','HTTP 403','HTTP 429','Falta credencial')):
                records.extend({'provider':provider,'target':t,'queried_at_utc':timestamp(),'status':'NO CONSULTADO',
                    'error':'Proveedor detenido por autenticación/permisos/cuota; reintentar después','data':None} for t in items[index+1:])
                break
    data['public_intelligence']={'records':records}
    correlate_cached(data,selected)
    return data

def correlate_cached(data,selected=()):
    records=data.get('public_intelligence',{}).get('records',[])
    from intel_context import extract_cves
    origins={}
    previous={c['cve']:c for c in data.get('public_intelligence',{}).get('correlations',[])}
    for record_row in records:
        if record_row.get('status')=='OK':
            for cve in extract_cves(record_row.get('data',{})):
                row=origins.setdefault(cve,{'assets':set(),'sources':set()})
                row['assets'].add(record_row['target']);row['sources'].add(record_row['provider'])
    for c in data.get('manual_checks',[]):
        for cve in extract_cves(c.get('evidence','')):
            row=origins.setdefault(cve,{'assets':set(),'sources':set()});row['assets'].add(c['asset']);row['sources'].add('Validación documentada')
    catalog=kev_catalog(); index={v['cveID']:v for v in catalog['vulnerabilities']}
    correlations=[]
    for cve,row in sorted(origins.items()):
        correlations.append({'cve':cve,'assets':sorted(row['assets']),'sources':sorted(row['sources']),'kev':index.get(cve),'epss':record('EPSS',cve) if 'EPSS' in selected else previous.get(cve,{}).get('epss'),
            'queried_at_utc':previous.get(cve,{}).get('queried_at_utc') or timestamp(),'status':'Indicio de fuente pública; aplicabilidad pendiente de comprobación'})
    data['public_intelligence']={'records':records,'correlations':correlations,'kev_version':catalog['catalogVersion'],
        'queried_at_utc':timestamp(),'scope_note':'IPs DNS son relaciones; no se atribuye actividad a la organización automáticamente'}
    return data

def record_from_kali(provider,target,key,remote):
    script=(ROOT/'abuse_diagnostic.py').read_text(encoding='utf-8')
    result=remote('Diagnóstico API '+provider,['python3','-c',script,'--stdin'],60,
                  json.dumps({'provider':provider,'target':target,'key':key}))
    if result['status']!='OK':
        return {'provider':provider,'target':target,'queried_at_utc':timestamp(),'origin':'Kali',
                'status':'ERROR','data':None,'error':'Diagnóstico remoto no completado: '+result.get('stderr','')}
    try:return sanitize(json.loads(result['output']),[key])
    except (ValueError,TypeError):return {'provider':provider,'target':target,'queried_at_utc':timestamp(),
        'origin':'Kali','status':'ERROR','data':None,'error':'Salida remota no JSON'}
