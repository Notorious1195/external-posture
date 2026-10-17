"""Bounded public HTTP/TLS/DNS checks performed from Kali; no private target access."""
import json
from posture import check
SCRIPT = r'''
import sys,json,socket,ssl,http.client,ipaddress,subprocess,re,hashlib,secrets
from urllib.parse import urlsplit,urljoin
args=json.load(sys.stdin); out=[]
def add(c,a,p=None,e='',ok=False,na=False):
 out.append({'control':c,'asset':a,'penalty':p,'evidence':e,'status':'No aplica' if na else ('Evaluado' if ok else 'No evaluado')})
def public(host):
 values=args.get('dns_ips',{}).get(host,[])
 if values:
  if any(not ipaddress.ip_address(a).is_global for a in values):raise ValueError('IP de transporte no pública')
  return values[0]
 addresses=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
 if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses): raise ValueError('Destino no público o mixto')
 return addresses[0][4][0]
def dmarc_policy(domain,organizational,lookup):
    """Check exact policy first, then DNS ancestors to organizational boundary.
    Conservative subset: ambiguous records/errors remain unknown; PSD not scored.
    """
    names=[];current=domain
    while True:
        names.append(current)
        if current==organizational:break
        if not current.endswith('.'+organizational):raise ValueError('Límite organizacional inválido')
        current=current.split('.',1)[1]
    logs=[]
    for name in names:
        records,raw=lookup('_dmarc.'+name);logs.append(raw)
        dm=[x for x in records if x.lower().startswith('v=dmarc1')]
        if not dm:continue
        if len(dm)!=1:raise ValueError('DMARC ambiguo: varios registros en '+name)
        tags={}
        for part in dm[0].split(';'):
            if '=' in part:
                k,v=part.strip().lower().split('=',1)
                if k in tags:raise ValueError('DMARC ambiguo: etiqueta duplicada '+k)
                tags[k]=v
        if tags.get('p') not in ('reject','quarantine','none'):raise ValueError('DMARC sin política p válida')
        policy=tags.get('sp',tags['p']) if name!=domain else tags['p']
        if policy not in ('reject','quarantine','none'):raise ValueError('DMARC sp inválida')
        pct=tags.get('pct','100')
        if not pct.isdigit() or not 0<=int(pct)<=100:raise ValueError('DMARC pct inválido')
        penalty=0 if policy=='reject' and int(pct)==100 else .25 if policy in ('reject','quarantine') else 1
        return penalty,{'queried_domain':domain,'policy_domain':name,'inherited':name!=domain,'effective_policy':policy,'pct':int(pct),'dns_responses':logs,'limits':'Comprobación de publicación; no verifica alineación ni entrega de correo; no aplica políticas PSD.'}
    return 1,{'queried_domain':domain,'organizational_domain':organizational,'effective_policy':'ausente','dns_responses':logs}

for url in args['urls']:
 u=urlsplit(url)
 try:
  ip=public(u.hostname); port=u.port or (443 if u.scheme=='https' else 80)
  if u.scheme=='https':
   ctx=ssl.create_default_context()
   try:
    with socket.create_connection((ip,port),timeout=8) as sock:
     with ctx.wrap_socket(sock,server_hostname=u.hostname) as tls:
      cert=tls.getpeercert();add('T-01',url,0,'TLS verificado; expires='+str(cert.get('notAfter'))+'; protocolo='+tls.version(),True)
   except ssl.SSLCertVerificationError as exc:
    code=getattr(exc,'verify_code',None)
    certain=code in (9,10,18,19,62,64)
    add('T-01',url,.6 if certain else None,'Verificación TLS código '+str(code)+': '+str(exc)+'; errores de emisor local requieren contraste del almacén CA',certain)
    ctx=ssl._create_unverified_context() # only to observe public HTTP; never declares trust validated
   conn=http.client.HTTPSConnection(u.hostname,port,timeout=8,context=ctx)
   sock=socket.create_connection((ip,port),timeout=8);conn.sock=ctx.wrap_socket(sock,server_hostname=u.hostname)
  else:
   conn=http.client.HTTPConnection(u.hostname,port,timeout=8);conn.sock=socket.create_connection((ip,port),timeout=8)
  original=(u,ip,port,ctx if u.scheme=='https' else None)
  effective=url;chain=[]
  for hop in range(4):
   conn.request('GET',(u.path or '/')+('?' + u.query if u.query else ''),headers={'User-Agent':'ExternalPosture/15.1','Accept':'text/html'})
   r=conn.getresponse();h={k.lower():v for k,v in r.getheaders()}
   if r.status not in (301,302,303,307,308) or not h.get('location'):break
   if hop==3:break
   target=urljoin(effective,h['location']);next_u=urlsplit(target)
   if next_u.scheme not in ('http','https') or not next_u.hostname:raise ValueError('Redirección no HTTP')
   name=next_u.hostname;root=args['domain']
   if not (name==root or name.endswith('.'+root) or name in args.get('explicit_ips',[])):raise ValueError('Redirección fuera del alcance; no seguida')
   if u.scheme=='https' and next_u.scheme=='http':raise ValueError('Redirección HTTPS a HTTP; requiere revisión')
   chain.append({'from':effective,'to':target,'status':r.status});r.read(8192);conn.close()
   u=next_u;ip=public(u.hostname);port=u.port or (443 if u.scheme=='https' else 80);effective=target
   if u.scheme=='https':
    redirect_ctx=ssl.create_default_context()
    conn=http.client.HTTPSConnection(u.hostname,port,timeout=8,context=redirect_ctx)
    sock=socket.create_connection((ip,port),timeout=8);conn.sock=redirect_ctx.wrap_socket(sock,server_hostname=u.hostname)
   else:
    conn=http.client.HTTPConnection(u.hostname,port,timeout=8);conn.sock=socket.create_connection((ip,port),timeout=8)
  html=any(t in h.get('content-type','').lower() for t in ('text/html','application/xhtml+xml'))
  evidence=json.dumps({'url':url,'effective_url':effective,'redirects':chain,'status':r.status,'headers':h},ensure_ascii=False)
  if u.scheme=='https':
   add('T-03',url,0,'Respuesta transportada por HTTPS; '+evidence,True)
   if original[0].scheme=='http':add('T-01',url,0,'HTTPS de redirección validado con almacén CA; '+evidence,True)
  elif 200<=r.status<300:
   add('T-03',url,1,'Contenido servido por HTTP sin redirección a HTTPS; '+evidence,True)
   for control in ('T-01','T-02'):add(control,url,e='El endpoint HTTP no utiliza TLS; la ausencia de transporte cifrado se penaliza una sola vez en T-03.',na=True)
  else:add('T-03',url,e='Respuesta insuficiente para confirmar transporte de la aplicación; '+evidence)
  if 200<=r.status<300 and html:
   x=h.get('x-frame-options','').upper();csp=h.get('content-security-policy','').lower()
   directive=next((x.strip() for x in csp.split(';') if x.strip().startswith('frame-ancestors ')),'')
   protected=x in ('DENY','SAMEORIGIN') or (bool(directive) and '*' not in directive and 'http:' not in directive and 'https:' not in directive)
   add('W-01',url,0 if protected else .25,evidence,True)
   add('W-02',url,0 if h.get('x-content-type-options','').lower()=='nosniff' else .25,evidence,True)
  else:
   for c in ('W-01','W-02'):add(c,url,e='No evaluable: requiere respuesta HTML 2xx. '+evidence)
  blocked=r.status in (401,403,429)
  r.read(8192);conn.close()
  if blocked:
   for control in ('V-02','V-03','V-04'):add(control,url,e='Acceso restringido en página inicial; prueba de rutas omitida')
   continue
  u,ip,port,original_ctx=original
  if original_ctx is not None:ctx=original_ctx
  def get(path):
   if u.scheme=='https':
    c=http.client.HTTPSConnection(u.hostname,port,timeout=8,context=ctx)
    sk=socket.create_connection((ip,port),timeout=8);c.sock=ctx.wrap_socket(sk,server_hostname=u.hostname)
   else:
    c=http.client.HTTPConnection(u.hostname,port,timeout=8);c.sock=socket.create_connection((ip,port),timeout=8)
   c.request('GET',path,headers={'User-Agent':'ExternalPosture/15','Accept':'*/*'})
   resp=c.getresponse();body=resp.read(16384).decode('utf-8','replace');status=resp.status;c.close()
   return status,body
  try: baseline_status,baseline=get('/__postura_missing_'+secrets.token_hex(8))
  except Exception: baseline_status,baseline=None,None
  definitions=[('V-02','/.git/HEAD'),('V-03','/.env'),('V-04','/phpinfo.php')]
  for control,path in definitions:
   try:
    status,body=get(path);different=baseline is not None and body!=baseline
    signature=False;keys=[]
    if control=='V-02':signature=bool(re.match(r'(?m)^ref: refs/heads/[A-Za-z0-9._/-]+\s*$',body.strip()))
    if control=='V-03':
     keys=re.findall(r'(?m)^\s*((?:DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|APP_KEY))\s*=\s*[^\s#]+',body)
     signature=bool(keys)
    if control=='V-04':signature='phpinfo()' in body.lower() and ('PHP Version' in body or 'phpinfo' in body.lower() and 'Configuration' in body)
    if status==200 and signature and different:
     add(control,url,.6 if control!='V-04' else .25,json.dumps({'path':path,'http':status,'signature':control,'key_names':keys,'body_sha256':hashlib.sha256(body.encode()).hexdigest(),'note':'Valores sensibles no se conservan; firma corroborada frente a ruta inexistente'}),True)
    elif status==403 and baseline_status==403:
     add(control,url,e='Acceso restringido también en ruta de contraste; no permite descartar exposición: HTTP 403')
    elif status in (403,404,410) or status==200 and baseline is not None and (not signature or not different):
     add(control,url,0,json.dumps({'path':path,'http':status,'note':'Sin exposición comprobada en esta ruta y momento; no evalúa todas las rutas'}),True)
    else:add(control,url,e='Respuesta no concluyente en '+path+': HTTP '+str(status))
   except Exception as exc:add(control,url,e='Prueba '+path+' no completada: '+type(exc).__name__)
 except Exception as exc:
  for c in ('W-01','W-02'):add(c,url,e=type(exc).__name__+': '+str(exc))
  if u.scheme=='https' and not any(x['control']=='T-01' and x['asset']==url for x in out):add('T-01',url,e=str(exc))
domain=args['domain']
def txt(name):
 logs=[]
 for resolver in ('1.1.1.1','8.8.8.8'):
  try:
   p=subprocess.run(['dig','@'+resolver,'+time=3','+tries=1','+noall','+comments','+answer',name,'TXT'],capture_output=True,text=True,timeout=10)
   logs.append(p.stdout+p.stderr)
   if p.returncode!=0 or not any('status: '+x in p.stdout for x in ('NOERROR','NXDOMAIN')):continue
   records=[]
   for line in p.stdout.splitlines():
    if '\tTXT\t' in line or ' TXT ' in line:records.append(''.join(re.findall(r'"([^\"]*)"',line)))
   return records,p.stdout
  except Exception as exc:logs.append(str(exc))
 raise ValueError('DNS TXT no completado: '+'; '.join(logs))
try:
 records,raw=txt(domain);spf=[x.lower() for x in records if x.lower().startswith('v=spf1')]
 p=0 if len(spf)==1 and spf[0].split()[-1]=='-all' else (.25 if len(spf)==1 and spf[0].split()[-1]=='~all' else 1)
 add('D-01',domain,p,raw,True)
except Exception as exc:add('D-01',domain,e=str(exc))
try:
 penalty,details=dmarc_policy(domain,args.get('organizational_domain',domain),txt)
 add('D-02',domain,penalty,json.dumps(details,ensure_ascii=False),True)
except Exception as exc:add('D-02',domain,e=str(exc))
print(json.dumps(out,ensure_ascii=False))
'''

def collect(data,run_tool,progress):
    urls=set()
    for r in data.get('results',[]):
        if r.get('tool')=='HTTPx Toolkit':
            for line in r.get('output','').splitlines():
                parts=line.split()
                if parts and parts[0].startswith(('http://','https://')):
                    from urllib.parse import urlsplit,urljoin
                    host=urlsplit(parts[0]).hostname or ''
                    if host==data['domain'] or host.endswith('.'+data['domain']) or host in data.get('explicit_ips',[]): urls.add(parts[0])
    rows=[]
    # One URL per invocation prevents a single timeout from losing all results.
    batches=sorted(urls) or [None]
    for index,url in enumerate(batches):
        progress.write(f'Controles públicos HTTP/TLS/DNS: {index+1}/{len(batches)}')
        from domain_policy import registrable_domain
        target={'organizational_domain':registrable_domain(data['domain']),'domain':data['domain'],'urls':[url] if url else [],'dns_ips':data.get('dns_ips',{}),'explicit_ips':data.get('explicit_ips',[])}
        r=run_tool('Controles postura · '+(url or data['domain']),['python3','-c',SCRIPT],180,json.dumps(target))
        data['results']=[x for x in data.get('results',[]) if x.get('tool')!=r['tool']]
        data['results'].append(r)
        if r['status']=='OK':
            try:
                for row in json.loads(r['output']):
                    c=check(row['control'],row['asset'],row['status'],row['penalty'],row['evidence'],'Prueba pública desde Kali')
                    rows=[x for x in rows if (x['control'],x['asset'])!=(c['control'],c['asset'])];rows.append(c)
            except (ValueError,KeyError,TypeError):r['status']='ERROR';r['stderr']='Salida de controles inválida'
    data['posture_probe']=rows
    return data
