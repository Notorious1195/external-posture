"""Conservative per-origin application access gate; transport stays assessable."""
from urllib.parse import urlsplit

def origin(url):
 p=urlsplit(url);return (p.scheme,p.hostname,p.port or (443 if p.scheme=='https' else 80))

def unavailable(data,url):
 for row in data.get('web_access',[])+data.get('web_preflight',[]):
  if origin(row.get('url',''))==origin(url) and (row.get('http_status') in (401,403,429) or row.get('blocked') or row.get('status')=='ERROR'):
   return True
 return False

def normalize(data):
 from nmap_checks import tls_checks
 # Reinterpret original XML when loading earlier checkpoints; never repair by guessing.
 rows=[]
 for result in data.get('results',[]):
  if result.get('tool','').startswith('Nmap web/TLS · '):
   url=result['tool'].split(' · ')[1]
   if url.startswith('https://'):rows.append(tls_checks(result,url))
 if rows:data['nmap_tls_checks']=rows
 for report in data.get('zap_reports',[]):
  report['application_evaluable']=not unavailable(data,report.get('url',''))
 return data

REMOTE_PROBE='''import urllib.request,urllib.error,sys,socket,ipaddress,json
from urllib.parse import urlsplit
u=sys.argv[1];h=urlsplit(u).hostname
assert all(ipaddress.ip_address(a[4][0]).is_global for a in socket.getaddrinfo(h,None,type=socket.SOCK_STREAM))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
try:
 try:r=urllib.request.build_opener(NoRedirect()).open(u,timeout=12)
 except urllib.error.HTTPError as e:r=e
 body=r.read(65536).decode('utf-8','replace').lower()
 signatures=('wpdef_lockout','wd_step_show_form','wordfence','cf-chl-','incapsula incident','defender-security')
 header=str(dict(r.headers)).lower()
 blocked=r.code in (401,403,429) or any(s in body+header for s in signatures)
 print(json.dumps({'url':u,'status':'OK','http_status':r.code,'blocked':blocked,'reason':'Acceso restringido o página de protección' if blocked else 'Respuesta obtenida'}))
except Exception as e:
 print(json.dumps({'url':u,'status':'ERROR','blocked':True,'reason':type(e).__name__+': acceso no comprobado'}))
'''
