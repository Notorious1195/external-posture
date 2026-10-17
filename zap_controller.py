"""Isolated ZAP daemon controlled via its localhost API, executed on Kali."""
import json,sys,os,re,time,socket,ipaddress,shutil,tempfile,subprocess,secrets
from urllib.error import HTTPError
from urllib.request import Request,build_opener,ProxyHandler
from urllib.parse import urlencode,urlsplit

def wait_for_completion(api,scan,url,initial_seconds=900,max_seconds=3600,stall_seconds=900,passive_max_seconds=1800,emit=None):
 """Wait independently per origin; progress extends beyond the initial budget."""
 emit=emit or (lambda event:None)
 start=time.monotonic();last_change=start;last_emit=-100;last_marker=None
 status=0;remaining=-1;reason='';complete=False;events=[]
 while True:
  status=int(api('clientSpider','view','status',scanId=scan)['status'])
  urls=api('core','view','urls',baseurl=url).get('urls',[])
  now=time.monotonic();marker=(status,len(set(urls)))
  if marker!=last_marker:last_change=now;last_marker=marker
  if now-last_emit>=10 or status==100:
   event={'phase':'Recorrido','percent':status,'urls':marker[1],'elapsed_seconds':int(now-start),'extended':now-start>=initial_seconds}
   events.append(event);emit(event);last_emit=now
  if status==100:complete=True;break
  if now-start>=max_seconds:reason='Límite máximo por sitio alcanzado';break
  if now-start>=initial_seconds and now-last_change>=stall_seconds:
   reason='Recorrido sin avance en porcentaje ni URLs durante '+str(stall_seconds)+' segundos';break
  time.sleep(2)
 if not complete:api('clientSpider','action','stop',scanId=scan)
 passive_start=time.monotonic();last_emit=-100
 while True:
  remaining=int(api('pscan','view','recordsToScan')['recordsToScan'])
  now=time.monotonic()
  if now-last_emit>=10 or remaining==0:
   event={'phase':'Análisis pasivo','percent':status,'passive_pending':remaining,'elapsed_seconds':int(now-start)}
   events.append(event);emit(event);last_emit=now
  if remaining==0:break
  if now-passive_start>=passive_max_seconds:
   reason=(reason+'; ' if reason else '')+'Límite de espera pasiva por sitio alcanzado';break
  time.sleep(2)
 return {'crawler_complete':complete,'crawler_progress':status,'passive_pending':remaining,
  'status':'OK' if complete and remaining==0 else 'PARCIAL','partial_reason':reason,
  'elapsed_seconds':int(time.monotonic()-start),'progress_events':events}


def execute(args):
 url=args['url'];u=urlsplit(url);domain=args['domain'];host=u.hostname or ''
 if u.scheme not in ('http','https') or u.username or u.password:raise ValueError('URL inválida')
 if not(host==domain or host.endswith('.'+domain) or host in args.get('explicit_ips',[])):raise ValueError('URL fuera de alcance')
 addresses=socket.getaddrinfo(host,u.port or 443,type=socket.SOCK_STREAM)
 if not addresses or any(not ipaddress.ip_address(x[4][0]).is_global for x in addresses):raise ValueError('DNS no público o mixto')
 binary=shutil.which('zaproxy') or shutil.which('zap.sh')
 if not binary:raise RuntimeError('ZAP no instalado: instala zaproxy en Kali')
 key=secrets.token_hex(24);opener=build_opener(ProxyHandler({}))
 with tempfile.TemporaryDirectory(prefix='postura-zap-') as work:
  plugins=os.path.expanduser('~/.ZAP/plugin')
  if os.path.isdir(plugins):
   shutil.copytree(plugins,os.path.join(work,'plugin'))
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  # Key is stored in a private configuration file, never in command output.
  cfg=os.path.join(work,'api.properties')
  with open(cfg,'w') as f:f.write('api.key='+key+'\nautoupdate.checkOnStart=false\nautoupdate.downloadNewRelease=false\nautoupdate.installAddonUpdates=false\n')
  os.chmod(cfg,0o600)
  log=open(os.path.join(work,'daemon.log'),'w')
  p=subprocess.Popen([binary,'-daemon','-host','127.0.0.1','-port',str(port),'-dir',work,'-configfile',cfg],stdout=log,stderr=log)
  def api(component,kind,name,**params):
   req=Request(f'http://127.0.0.1:{port}/JSON/{component}/{kind}/{name}/',data=urlencode(params).encode(),headers={'X-ZAP-API-Key':key})
   try:
    with opener.open(req,timeout=12) as r:obj=json.load(r)
   except HTTPError as e:
    body=e.read(4096).decode('utf-8','replace').replace(key,'[REDACTADO]')
    raise RuntimeError(f'API {component}/{kind}/{name}: HTTP {e.code}; {body}') from None
   if 'code' in obj:raise RuntimeError('ZAP '+str(obj.get('code'))+': '+str(obj.get('message','')))
   return obj
  try:
   deadline=time.monotonic()+100
   while True:
    try:version=api('core','view','version')['version'];break
    except Exception:
     if p.poll() is not None or time.monotonic()>deadline:raise RuntimeError('ZAP no inició; comprueba Java y complementos')
     time.sleep(2)
   api('core','action','setMode',mode='protect')
   context='postura';api('context','action','newContext',contextName=context)
   pattern=re.escape(u.scheme+'://'+u.netloc)+r'(?:/.*)?'
   api('context','action','includeInContext',contextName=context,regex=pattern)
   api('context','action','setContextInScope',contextName=context,booleanInScope='true')
   api('pscan','action','setScanOnlyInScope',onlyInScope='true')
   addons=api('autoupdate','view','installedAddons').get('installedAddons',[])
   installed={a.get('id') for a in addons}
   missing={'client','selenium','pscan','pscanrules'}-installed
   if missing:raise RuntimeError('Faltan complementos ZAP: '+', '.join(sorted(missing)))
   budget=900
   maximum=max(budget,min(14400,int(args.get('max_seconds',3600))))
   passive_max=max(60,min(7200,int(args.get('passive_max_seconds',1800))))
   scan_response=api('clientSpider','action','scan',url=url,contextName=context,browser='firefox-headless',subtreeOnly='true',maxCrawlDepth='0',numberOfBrowsers='1',scopeCheck='STRICT')
   scan=scan_response.get('scanId',scan_response.get('scan'))
   if scan is None or isinstance(scan,(dict,list,bool)) or not str(scan).isdigit():
    raise RuntimeError('API clientSpider/action/scan: respuesta sin identificador válido: '+json.dumps(scan_response,ensure_ascii=False))
   scan=str(scan)

   def emit(event):
    print('ZAP_PROGRESS '+json.dumps(event,ensure_ascii=False),file=sys.stderr,flush=True)
   try:
    completion=wait_for_completion(api,scan,u.scheme+'://'+u.netloc,budget,maximum,900,passive_max,emit)
   except Exception as exc:
    try:api('clientSpider','action','stop',scanId=scan)
    except Exception:pass
    completion={'status':'PARCIAL','crawler_complete':False,'crawler_progress':None,'passive_pending':None,'partial_reason':'Fallo al supervisar ZAP: '+str(exc).replace(key,'[REDACTADO]'),'progress_events':[]}
   urls=api('core','view','urls',baseurl=u.scheme+'://'+u.netloc).get('urls',[])
   alerts=[];start=0
   while True:
    batch=api('core','view','alerts',baseurl=u.scheme+'://'+u.netloc,start=start,count=100).get('alerts',[])
    for a in batch:
     alerts.append({k:a.get(k,'') for k in ('pluginId','alertRef','name','risk','confidence','url','param','description','solution','reference','evidence','otherinfo','messageId','attack','cweid')})
    if len(batch)<100:break
    start+=100
   messages=[];message_errors=[];seen=set();forms=[]
   from html.parser import HTMLParser
   from urllib.parse import urljoin
   class FormParser(HTMLParser):
    def __init__(self,page):super().__init__();self.page=page;self.current=None
    def handle_starttag(self,tag,attrs):
     a=dict(attrs)
     if tag.lower()=='form':self.current={'page':self.page,'action':urljoin(self.page,a.get('action') or self.page),'method':a.get('method','GET').upper(),'password_fields':[]}
     elif tag.lower()=='input' and self.current is not None and a.get('type','').lower()=='password':self.current['password_fields'].append(a.get('name','sin nombre'))
    def handle_endtag(self,tag):
     if tag.lower()=='form' and self.current:
      if self.current['password_fields'] and self.current not in forms:forms.append(self.current)
      self.current=None
   def redact(value):
    value=re.sub(r'(?im)^((?:Authorization|Cookie|Set-Cookie|X-API-Key|Auth-Key):)[^\r\n]*',r'\1 [REDACTADO]',str(value))
    return re.sub(r'((?:ASP\.NET_SessionId|PHPSESSID|JSESSIONID|access_token|tbPassword)\s*=\s*)[^;\s&"<>]+',r'\1[REDACTADO]',value,flags=re.I)
   for a in alerts:
    mid=str(a.get('messageId',''))
    if not mid.isdigit() or mid in seen:continue
    seen.add(mid)
    if len(messages)>=128:
     message_errors.append({'messageId':mid,'reason':'Límite de retención de mensajes; alerta conservada'});continue
    try:
     m=api('core','view','message',id=mid).get('message',{})
     page=a.get('url','');parser=FormParser(page);parser.feed(m.get('responseBody',''))
     import hashlib
     row={'messageId':mid,'url':page,'requestHeader':redact(m.get('requestHeader',''))[:4096],'responseHeader':redact(m.get('responseHeader',''))[:4096],'responseBodyExcerpt':redact(m.get('responseBody',''))[:2048],'responseBodySHA256':hashlib.sha256(m.get('responseBody','').encode()).hexdigest(),'body_excerpt':True}
     messages.append(row)
    except Exception as exc:message_errors.append({'messageId':mid,'reason':type(exc).__name__})
   for a in alerts:
    for field in ('evidence','otherinfo','attack'):a[field]=redact(a.get(field,''))
   return {'url':url,'version':version,'start_response':scan_response,**completion,'crawl_budget_seconds':budget,'max_crawl_seconds':maximum,'max_passive_seconds':passive_max,'urls':urls,'alerts':alerts,'messages':messages,'message_errors':message_errors,'password_forms':forms,'scope':pattern,'profile':'Client Spider sin límite de profundidad y análisis pasivo; sin active scan'}
  finally:
   try:api('core','action','shutdown')
   except Exception:pass
   try:p.wait(timeout=15)
   except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=10)
   log.close()
if __name__=='__main__':
 try:print(json.dumps(execute(json.load(sys.stdin)),ensure_ascii=False))
 except Exception as e:print(json.dumps({'status':'ERROR','error':str(e)},ensure_ascii=False));sys.exit(1)
