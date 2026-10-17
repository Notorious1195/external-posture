"""Offline behavioral checks; no network and no scan against real assets."""
import os
import ast,json,re,shlex,posixpath,ipaddress,hashlib
import xml.etree.ElementTree as ET
from datetime import datetime,timezone
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import urlsplit
from assets import dns_ip_map,public_ips
from intelligence import build_observations

def backend_functions():
    tree=ast.parse(Path(__file__).with_name('backend.py').read_text(encoding='utf-8'))
    funcs=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))]
    env=dict(os=os,hashlib=hashlib,json=json,re=re,shlex=shlex,posixpath=posixpath,ipaddress=ipaddress,ET=ET,urlsplit=urlsplit,
             datetime=datetime,timezone=timezone,SimpleNamespace=SimpleNamespace,
             DOMAIN=re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',re.I),
             ANSI=re.compile(r'\x1b\[[0-9;]*[A-Za-z]'),dns_ip_map=dns_ip_map,public_ips=public_ips,build_observations=build_observations,
             st=SimpleNamespace(session_state={'connection':{},'model_config':{},'api_config':{'ct_enabled':False,'amass_enabled':False,'nuclei_enabled':False}}))
    exec(compile(ast.Module(body=funcs,type_ignores=[]),'backend.py','exec'),env)
    return env

def test_inventory_and_resume():
    env=backend_functions(); calls=[]; checkpoints=[]
    hosts=['h%03d.example.com'%i for i in range(105)]
    def fake(name,args,timeout=90,input_text=None):
        calls.append(name)
        output=''
        if name=='Subfinder': output='\n'.join(hosts)
        elif name=='DNSx':output='\n'.join(h+' [8.8.8.8]' for h in hosts)
        elif name=='HTTPx Toolkit':output='\n'.join('https://'+h+' [200]' for h in hosts[:12])
        elif name.startswith('Acceso antes de pruebas · '):output=json.dumps({'url':args[-1],'status':'OK','http_status':200,'blocked':False})
        elif name.startswith('Nmap · '):output='<nmaprun><host><address addr="8.8.8.8"/><ports><port portid="443" protocol="tcp"><state state="open"/><service name="https"/></port></ports></host></nmaprun>'
        return dict(tool=name,status='OK',exit=0,output=output,stderr='',command=' '.join(shlex.quote(x) for x in args))
    env['run_tool']=fake;env['save_checkpoint']=lambda d:checkpoints.append(json.loads(json.dumps(d)))
    env['capture_web']=lambda *args:dict(id='TEST',url=args[0])
    progress=SimpleNamespace(write=lambda *args:None)
    inventory=env['recognize']('example.com',progress,['1.1.1.1'])
    assert len(inventory['hosts'])==106
    assert not any(n.startswith(('Nmap ·','Nuclei ·','FFUF')) for n in calls)
    inventory['hosts']=inventory['hosts'][:3]
    evaluated=env['evaluate_inventory'](inventory,progress)
    assert len(evaluated['scanned'])==106
    assert not any(n.startswith(('Nuclei · ','Naabu · ','testssl · ')) for n in calls)
    assert sum(n.startswith('Nmap web/TLS · ') for n in calls)==12
    assert sum(n.startswith('Nikto · ') for n in calls)==12
    assert sum(n.startswith('FFUF · ') for n in calls)==12
    old_count=len(calls)
    resumed=env['evaluate_inventory'](evaluated,progress)
    assert all(n.startswith('Acceso antes de pruebas · ') for n in calls[old_count:]), 'Only fresh access checks may run again'
    assert len(resumed['ports'])==106, 'Resume must not duplicate port rows'
    assert checkpoints and all('connection' not in c for c in checkpoints)
    print('PASS: public full inventory 106 targets, pinned Nmap, 12 NSE/Nikto URLs, no Naabu/testssl, cached resume')

if __name__=='__main__':test_inventory_and_resume()
