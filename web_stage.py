"""Browser corroboration and ZAP collection; findings remain indications."""
import json
from pathlib import Path

def collect(data,run_tool,progress,zap_enabled=True):
 zap_enabled=True  # Mandatory on evaluable web applications, even for legacy callers.
 from posture import checks_for
 from backend import capture_web
 from urllib.parse import urlsplit
 urls=sorted({c['asset'] for c in checks_for(data) if c['dimension']=='W'})
 access=[];zap=[]
 for url in urls:
  progress.write('Acceso web y navegador · '+url)
  evidence=next((c.get('evidence','') for c in data.get('posture_probe',[]) if c['asset']==url and c['control']=='W-01'),'')
  try:response=json.loads(evidence[evidence.index('{'):])
  except (ValueError,KeyError):response={}
  row={'url':url,'http_status':response.get('status'),'headers':response.get('headers',{}),'redirects':response.get('redirects',[]),'application_access':'Acceso restringido' if response.get('status') in (401,403) else ('Respuesta HTML evaluada' if response.get('status') and 200<=response['status']<300 else 'Pendiente'),'browser':'Pendiente'}
  try:
   visual=capture_web(url,data['domain'],progress,data.get('explicit_ips',[]))
   data['visual_evidence']=[v for v in data.get('visual_evidence',[]) if not(v.get('url')==url and v.get('source')=='Chromium en Kali')]+[visual];row['browser']='Captura obtenida; contrastar contenido y estado HTTP'
  except Exception as e:row['browser']='Error: '+str(e)[:250]
  access.append(row)
  from access_policy import unavailable
  if row.get("http_status") in (401,403,429) or unavailable(data,url):
   row["application_access"]="No evaluable: acceso restringido o no comprobado"
   zap.append({"url":url,"status":"NO EVALUADO","application_evaluable":False,"alerts":[],"reason":row["application_access"]})
   continue
  if zap_enabled:
   from backend import st
   maximum=int(st.session_state.get('zap_max_minutes',60))*60
   passive_max=int(st.session_state.get('zap_passive_max_minutes',30))*60
   progress.write('ZAP · '+url+' · 15 minutos iniciales por sitio, espera ampliable mientras avanza')
   live=progress.empty()
   def show(event):
    pending=event.get('passive_pending')
    live.write('ZAP · '+url+' · '+event.get('phase','')+' · '+str(event.get('percent'))+'% · '+('pendientes: '+str(pending) if pending is not None else 'URLs: '+str(event.get('urls',0)))+' · '+str(event.get('elapsed_seconds',0)//60)+' min'+(' · espera ampliada' if event.get('extended') else ''))
   result=run_tool('ZAP · '+url,['python3','-c',Path(__file__).with_name('zap_controller.py').read_text()],maximum+passive_max+300,json.dumps({'url':url,'domain':data['domain'],'explicit_ips':data.get('explicit_ips',[]),'seconds':900,'max_seconds':maximum,'passive_max_seconds':passive_max}),progress_callback=show)
   data['results']=[r for r in data.get('results',[]) if r['tool']!=result['tool']]+[result]
   try:
    report=json.loads(result['output'])
    from redaction import utf8
    if report.get('profile'):report['profile']=utf8(report['profile'])
   except ValueError:report={'url':url,'status':'ERROR','error':result.get('stderr','Salida ZAP inválida')}
   report['url']=url;result['status']=report.get('status','ERROR');zap.append(report)
 data['web_access']=access;data['zap_reports']=zap
 return data
