"""Passive IP candidates. A relationship never grants authorization to scan an IP."""
import hashlib,ipaddress,json,re
from public_sources import request_json,record,timestamp,sanitize

def public4(value):
 try:
  ip=ipaddress.ip_address(str(value));return str(ip) if ip.version==4 and ip.is_global else None
 except ValueError:return None

def scoped(name,domain):
 name=str(name).lower().rstrip('.').removeprefix('*.')
 return name==domain or name.endswith('.'+domain)

def extract(provider,hit):
 if provider=='Shodan':
  cert=hit.get('ssl',{}).get('cert',{})
  names=hit.get('hostnames',[])+hit.get('domains',[])+[cert.get('subject',{}).get('CN','')]
  ext=cert.get('extensions',[])
  if isinstance(ext,list):
   for x in ext:
    if x.get('name')=='subjectAltName':names+=re.findall(r'DNS:([^,\s]+)',str(x.get('data','')))
  return public4(hit.get('ip_str')),{'names':sorted(set(n for n in names if n)),'org':hit.get('org'),'asn':hit.get('asn'),'observed_at':hit.get('timestamp'),'cert_sha256':cert.get('fingerprint',{}).get('sha256')}
 kind=str(hit.get('resource_type','')).lower()
 host=hit.get('host',{}) or (hit.get('resource',{}) if kind=='host' else {})
 ip=public4(host.get('ip') or hit.get('ip') or (hit.get('id') if kind=='host' else None))
 names=list(host.get('dns',{}).get('names',[]) or [])
 reverse=host.get('dns',{}).get('reverse_dns',{}).get('names',[]) or [];names+=reverse
 for service in host.get('services',[]) or []:names+=service.get('cert',{}).get('names',[]) or []
 matched=hit.get('matched_fields',{})
 if isinstance(matched,dict):
  for field,values in matched.items():
   if field.endswith('.names'):names+=values if isinstance(values,list) else [values]
 return ip,{'names':sorted(set(str(n) for n in names if n)),'org':host.get('autonomous_system',{}).get('name'),'asn':host.get('autonomous_system',{}).get('asn'),'observed_at':host.get('last_updated_at'),'cert_sha256':None}

def queries(domain,organization):
 safeorg=str(organization or '').replace('"','').replace('\\','').strip()[:100]
 # Query hits remain candidates even if a provider matches a broader organization.
 sh=[('Dominio en DNS',f'hostname:"{domain}"'),('Dominio en certificado',f'ssl.cert.subject.cn:"{domain}"')]
 ce=[('Dominio en certificado',f'host.services.cert.names = "{domain}" or host.services.cert.names = "*.{domain}"'),('Dominio en DNS',f'host.dns.names: "{domain}"')]
 if safeorg and safeorg.lower()!=domain:
  sh.append(('Organización declarada',f'org:"{safeorg}"'))
  ce.append(('Organización en certificado',f'host.services.cert.parsed.subject.organization = "{safeorg}"'))
 return {'Shodan':sh,'Censys':ce}

def discover(data,config,progress,request=None,rdap=None,remote=None):
 request=request or request_json;rdap=rdap or record
 keys=config.get('keys',{});maximum=int(config.get('ip_search_max_pages',5));maximum=max(1,min(maximum,100))
 candidates={};logs=[]
 def add(ip,provider,basis,query,info):
  if not ip:return
  row=candidates.setdefault(ip,{'ip':ip,'sources':[],'evidence':[],'names':[],'queried_at_utc':timestamp(),'status':'Candidata; atribución y autorización pendientes'})
  row['sources']=sorted(set(row['sources']+[provider]));row['names']=sorted(set(row['names']+info.get('names',[])))
  entry={'provider':provider,'basis':basis,'query':query,**info}
  if entry not in row['evidence']:row['evidence'].append(entry)
 # Retain exact DNSDumpster addresses as candidates, not IP ranges from banners/ASN.
 for section in ('a','cname','mx','ns'):
  for item in (data.get('dnsdumpster') or {}).get(section,[]):
   names=[item.get('host','')]
   for value in item.get('ips',[]) or []:
    raw=value.get('ip') if isinstance(value,dict) else value
    add(public4(raw),'DNSDumpster','Registro público','dominio: '+data['domain'],{'names':names})
 for provider,qrows in queries(data['domain'],data.get('organization')).items():
  key=keys.get(provider,'')
  if not key:
   logs.append({'provider':provider,'status':'NO CONFIGURADO','reason':'Falta clave para búsqueda pasiva de IPs'});continue
  stop=False
  for basis,query in qrows:
   if stop:break
   cursor='';seen=set();received=0;log={'provider':provider,'query':query,'basis':basis,'status':'OK','pages':0,'queried_at_utc':timestamp()}
   for page in range(1,maximum+1):
    progress.write(f'Descubrimiento IP · {provider} · {basis} · página {page}')
    try:
     if provider=='Shodan':
      obj=request('GET','https://api.shodan.io/shodan/host/search',params={'key':key,'query':query,'page':page,'minify':False})
      if not isinstance(obj.get('matches'),list) or 'total' not in obj:raise ValueError('Contrato de búsqueda Shodan inesperado')
      hits=obj['matches'];received+=len(hits);more=received<int(obj['total']);next_cursor=str(page+1)
     else:
      body={'query':query,'page_size':100,'fields':['host.ip','host.dns.names','host.dns.reverse_dns.names','host.autonomous_system','host.services.cert.names','host.last_updated_at']}
      if cursor:body['page_token']=cursor
      obj=request('POST','https://api.platform.censys.io/v3/global/search/query',headers={'Authorization':'Bearer '+key},json=body)
      result=obj.get('result',{})
      if not isinstance(result.get('hits'),list):raise ValueError('Contrato de búsqueda Censys inesperado')
      hits=result['hits'];next_cursor=result.get('next_page_token','');more=bool(next_cursor)
     obj=sanitize(obj,[key]);log['pages']=page
     unknown=0
     for hit in sanitize(hits,[key]):
      ip,info=extract(provider,hit);add(ip,provider,basis,query,info)
      if not ip and provider=='Censys' and not hit.get('host') and not hit.get('resource'):unknown+=1
     if unknown:log.update(status='PARCIAL',reason='Hay resultados cuyo contrato no permitió extraer una IP; conservar límite de cobertura')
     if not more:break
     if not hits or next_cursor in seen:
      log.update(status='PARCIAL',reason='Paginación sin avance; no se declara búsqueda completa');break
     seen.add(next_cursor);cursor=next_cursor
     if page==maximum:log.update(status='PARCIAL',reason='Límite configurado de páginas; búsqueda no exhaustiva',next_page=cursor)
    except Exception as exc:
     message=str(exc).replace(key,'[REDACTADO]');log.update(status='PARCIAL' if log['pages'] else 'ERROR',reason=message[:400])
     if getattr(exc,'status',None) in (401,403,429):stop=True
     break
   logs.append(log)
 if remote and candidates:
  ips=sorted(candidates)
  for start in range(0,len(ips),10):
   batch=ips[start:start+10]
   progress.write('Consultando DNS inverso público · lote '+str(start//10+1))
   result=remote('DNS inverso IP · '+str(start//10+1),['python3','-c',PTR_SCRIPT],75,json.dumps(batch))
   data.setdefault('results',[]).append(result)
   try:ptrs=json.loads(result.get('output','')) if result.get('status')=='OK' else {}
   except ValueError:ptrs={}
   for ip in batch:
    ptr=ptrs.get(ip,{'status':'ERROR','names':[],'reason':'Consulta PTR no completada'})
    candidates[ip]['reverse_dns']=ptr
    candidates[ip]['names']=sorted(set(candidates[ip]['names']+ptr.get('names',[])))
 dns={ip for values in data.get('dns_ips',{}).values() for ip in values}
 for ip,row in sorted(candidates.items()):
  row['inventory_names']=sorted(n for n,values in data.get('dns_ips',{}).items() if ip in values)
  row['no_fqdn_observed']=not(row['names'] or row['inventory_names'])
  progress.write('Contraste RDAP · '+ip)
  rr=rdap('RDAP',ip,'',True);row['rdap']=rr
  obj=rr.get('data') or {};row['rdap_context']={k:obj.get(k) for k in ('name','handle','country','startAddress','endAddress')}
  relation=any(scoped(n,data['domain']) for n in row['names']) or ip in dns
  row['relation']='Nombre o certificado relacionado; titularidad no demostrada' if relation else 'Coincidencia de fuente pública; atribución pendiente'
  row['eligible']=ip in data.get('explicit_ips',[])
  if row['eligible']:row['status']='IP declarada autorizada por el operador'
 data['ip_candidates']=list(candidates.values());data['ip_discovery']={'queries':logs,'queried_at_utc':timestamp(),'max_pages':maximum,'limits':'IPv4; resultados y cuotas de fuentes públicas. Sin expansión de ASN/rangos. Las relaciones no prueban titularidad y no habilitan sondeo directo.'}
 return data

def authorize(data,ips,reference):
 if not reference.strip():raise ValueError('Indica la referencia de alcance o autorización para estas IPs')
 allowed={r['ip']:r for r in data.get('ip_candidates',[])}
 if not set(ips)<=set(allowed):raise ValueError('Solo pueden incorporarse IPs candidatas conservadas')
 for ip in ips:
  if not public4(ip):raise ValueError('IP no pública o no IPv4')
  allowed[ip].update(eligible=True,status='Atribución y autorización confirmadas por el operador',authorization_reference=reference.strip(),authorized_at_utc=timestamp())
 data['explicit_ips']=sorted(set(data.get('explicit_ips',[]))|set(ips));data['hosts']=sorted(set(data.get('resolved',[]))|set(data['explicit_ips']))
 data.pop('report_preparation',None)
 return data


PTR_SCRIPT=r'''import json,sys,subprocess,ipaddress
out={}
for value in json.load(sys.stdin):
 ip=ipaddress.ip_address(value)
 assert ip.version==4 and ip.is_global
 try:
  p=subprocess.run(['dig','-x',str(ip),'+short','+time=2','+tries=1'],capture_output=True,text=True,timeout=6)
  out[value]={'status':'OK' if p.returncode==0 else 'ERROR','names':[s.strip().rstrip('.') for s in p.stdout.splitlines() if s.strip() and not s.startswith(';') and ' ' not in s] if p.returncode==0 else [],'reason':'PTR observado no acredita titularidad'}
 except Exception as e:out[value]={'status':'ERROR','names':[],'reason':type(e).__name__}
print(json.dumps(out))
'''
