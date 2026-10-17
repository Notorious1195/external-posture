"""Run on Kali: python3 abuse_diagnostic.py. Key is prompted, never printed."""
import json,sys,os,socket,ssl,getpass
from datetime import datetime,timezone
from urllib.request import Request,build_opener,HTTPSHandler,HTTPRedirectHandler
from urllib.parse import urlencode,urlsplit
from urllib.error import HTTPError,URLError

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        raise HTTPError(request.full_url,code,'Redirección API no seguida para proteger Auth-Key',headers,fp)

ENDPOINTS={'URLhaus':'https://urlhaus-api.abuse.ch/v1/host/',
           'ThreatFox':'https://threatfox-api.abuse.ch/api/v1/'}

def diagnose(provider,target,key):
    row={'provider':provider,'target':target,'queried_at_utc':datetime.now(timezone.utc).isoformat(),
         'origin':'Kali','status':'ERROR','data':None,'diagnostic':{'proxy_configured':any(os.environ.get(k) for k in ('HTTPS_PROXY','https_proxy'))}}
    if provider not in ENDPOINTS:row['error']='Proveedor no soportado';return row
    if not key:row['error']='Falta Auth-Key';return row
    endpoint=ENDPOINTS[provider];host=urlsplit(endpoint).hostname
    try:row['diagnostic']['dns_addresses']=sorted({x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)})
    except OSError:row['error']='DNS del proveedor no resolvió desde Kali';return row
    payload=urlencode({'host':target}).encode() if provider=='URLhaus' else json.dumps({'query':'search_ioc','search_term':target,'exact_match':True}).encode()
    headers={'Auth-Key':key,'Content-Type':'application/x-www-form-urlencoded' if provider=='URLhaus' else 'application/json','User-Agent':'ExternalPosture/15.1'}
    request=Request(endpoint,data=payload,headers=headers,method='POST')
    try:
        with build_opener(HTTPSHandler(context=ssl.create_default_context()),NoRedirect()).open(request,timeout=30) as response:
            row['diagnostic']['http_status']=response.status
            raw=response.read(8_000_001)
            if len(raw)>8_000_000:raise ValueError('Respuesta supera 8 MB')
            obj=json.loads(raw)
            row['data']=obj
            state=obj.get('query_status') if isinstance(obj,dict) else None
            row['diagnostic']['query_status']=state
            if state in ('ok','no_result','no_results','no_results_found'):
                row['status']='OK'
                row['diagnostic']['interpretation']='Sin coincidencias en esta consulta' if state!='ok' else 'Respuesta con datos'
            else:row['error']='El proveedor respondió pero rechazó la consulta: '+str(state)
    except HTTPError as exc:
        row['diagnostic']['http_status']=exc.code
        row['diagnostic']['retry_after']=exc.headers.get('Retry-After')
        row['error']='HTTP '+str(exc.code)+'; comprobar permisos, Auth-Key, cuota o licencia'
        row['diagnostic']['response_excerpt']=exc.read(4096).decode('utf-8','replace')
    except URLError as exc:
        row['error']='TLS/CA' if isinstance(exc.reason,ssl.SSLError) else 'Conectividad/proxy/timeout'
    except (TimeoutError,OSError):row['error']='Conectividad/timeout desde Kali'
    except (ValueError,TypeError):row['error']='Respuesta no JSON o formato/tamaño no admitido'
    # Upstream services must not be able to echo the key into saved output.
    return json.loads(json.dumps(row,ensure_ascii=False).replace(key,'[REDACTADO]'))

if __name__=='__main__':
    if '--stdin' in sys.argv:
        cfg=json.load(sys.stdin);print(json.dumps(diagnose(cfg['provider'],cfg['target'],cfg['key']),ensure_ascii=False))
    else:
        target=input('Dominio o IP a consultar: ').strip()
        key=getpass.getpass('Auth-Key abuse.ch (oculta): ').strip()
        output=[diagnose(p,target,key) for p in ENDPOINTS]
        with open('diagnostico_abuse_kali.json','w',encoding='utf-8') as file:json.dump(output,file,ensure_ascii=False,indent=2)
        for row in output:print(row['provider'],row['status'],row.get('error',row['diagnostic'].get('interpretation','')))
        print('Guardado: diagnostico_abuse_kali.json (sin Auth-Key)')
