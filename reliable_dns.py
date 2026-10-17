"""Preserve public DNS answers and exclusions; do not depend on Kali's local resolver."""
import ipaddress,json
SCRIPT=r'''
import sys,json,subprocess,ipaddress,socket
items=json.load(sys.stdin);out={}
for host in items:
 row={'addresses':[],'attempts':[],'status':'Sin resolución pública'}
 for resolver in ('1.1.1.1','8.8.8.8'):
  try:
   p=subprocess.run(['dig','@'+resolver,'+time=2','+tries=1','+noall','+comments','+answer',host,'A'],capture_output=True,text=True,timeout=6)
   row['attempts'].append({'resolver':resolver,'exit':p.returncode,'output':p.stdout,'stderr':p.stderr})
   for line in p.stdout.splitlines():
    parts=line.split()
    if len(parts)>=5 and parts[-2]=='A':
     try:
      a=ipaddress.ip_address(parts[-1])
      if a.version==4 and a.is_global:row['addresses'].append(str(a))
     except ValueError:pass
   if row['addresses']:break
  except Exception as exc:row['attempts'].append({'resolver':resolver,'error':str(exc)})
 if not row['addresses']:
  try:
   row['addresses']=[a[4][0] for a in socket.getaddrinfo(host,None,socket.AF_INET,socket.SOCK_STREAM) if ipaddress.ip_address(a[4][0]).is_global]
   row['attempts'].append({'resolver':'Sistema; fallback','addresses':row['addresses']})
  except Exception as exc:row['attempts'].append({'resolver':'Sistema; fallback','error':str(exc)})
 row['addresses']=sorted(set(row['addresses']));row['status']='Elegible' if row['addresses'] else 'Sin resolución pública'
 out[host]=row
print(json.dumps(out))
'''

def resolve(candidates,run_tool,progress):
    records={};results=[]
    # Small batches keep a failure from losing the entire inventory.
    for start in range(0,len(candidates),5):
        batch=candidates[start:start+5]
        progress.write('Comprobando DNS público: '+', '.join(batch))
        r=run_tool('DNS público · '+str(start//5+1),['python3','-c',SCRIPT],90,json.dumps(batch));results.append(r)
        if r['status']=='OK':
            try:records.update(json.loads(r['output']))
            except (ValueError,TypeError):r['status']='ERROR';r['stderr']='Respuesta DNS inválida'
        for host in batch:records.setdefault(host,{'addresses':[],'status':'DNS no completado','attempts':[]})
    return records,results

def targets(data,host):
    values=data.get('dns_ips',{}).get(host,[]) if host not in data.get('explicit_ips',[]) else [host]
    result=[]
    for value in values:
        try:
            if ipaddress.ip_address(value).is_global:result.append(value)
        except ValueError:pass
    return sorted(set(result))
