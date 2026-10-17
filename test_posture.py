"""Meaningful offline tests: missing data, extremes, deduplication and credential hygiene."""
import json
import math
import sys
import types
from pathlib import Path
from posture import calculate,checks_for,check

fixture={'domain':'example.com','date':'2026-09-30','hosts':['example.com'],'resolved':['example.com'],
 'explicit_ips':[],'subdomains':['example.com'],'dns_ips':{'example.com':['8.8.8.8']},
 'scanned':[],'ports':[],'results':[{'tool':'HTTPx Toolkit','status':'OK','output':'https://example.com [200]','stderr':''}],
 'observations':[],'visual_evidence':[],'coverage':{'candidates':1,'dns_a':1,'scanned':0,'selected':1,'open_ports':0,'historical_urls':0,'incomplete_tools':[]}}

p=calculate(fixture)
assert p['score']==0 and p['interval']==[0,100] and not p['complete']
fixture['manual_checks']=[check(r['control'],r['asset'],'Evaluado',0,'External proof') for r in checks_for(fixture)]
p=calculate(fixture)
assert p['score']==100 and p['complete'] and p['category']=='Favorable'
fixture['manual_checks']=[check(r['control'],r['asset'],'Evaluado',1,'External proof') for r in checks_for(fixture)]
p=calculate(fixture)
assert p['score']==0 and p['category']=='Crítica' and p['critical_alerts']
fixture['manual_checks']=[]
fixture['scanned']=['example.com'];fixture['ports']=[{'host':'example.com','port':'443','protocol':'tcp'}]
p=calculate(fixture)
assert 0<p['score']<100 and not p['complete'] and p['interval'][0]<p['interval'][1]
fixture['ports'].append({'host':'example.com','port':'3389','protocol':'tcp'})
p=calculate(fixture);assert p['observed_score']<100
for value in [-1,2,float('nan')]:
 try:check('V-01','example.com','Evaluado',value,'e');raise AssertionError('Invalid score accepted')
 except ValueError:pass
# mock requests only if unavailable; tests don't use network
try:import requests
except ImportError:
 requests=types.ModuleType('requests');requests.RequestException=Exception;sys.modules['requests']=requests
import public_sources as ps
assert ps.sanitize({'echo':'SECRET'},['SECRET'])=={'echo':'[REDACTADO]'}
catalog=ps.kev_catalog();assert catalog['count']==len(catalog['vulnerabilities'])
calls=[]
def lookup(provider,target,key='',is_ip=False):
 calls.append((provider,target));return {'query_status':'no_result'}
ps.lookup=lookup
from types import SimpleNamespace
fixture['public_intelligence']={}
ps.enrich(fixture,{'enabled':['RDAP','ThreatFox'],'keys':{'ThreatFox':'SECRET'},'abuse_via_kali':False},SimpleNamespace(write=lambda *a:None))
assert ('RDAP','example.com') in calls and ('RDAP','8.8.8.8') in calls
assert 'SECRET' not in json.dumps(fixture['public_intelligence'])
from intelligence import build_observations
fixture['observations'],fixture['coverage']=build_observations(fixture)
from docx_report import report_docx
from docx import Document
from io import BytesIO
report=report_docx(fixture);doc=Document(BytesIO(report))
assert any('Postura de seguridad externa' in p.text for p in doc.paragraphs)
assert any('experimental' in p.text for p in doc.paragraphs)
print('PASS: unknown data not healthy, score extremes, sensitive exposure, invalid values, API redaction, KEV, DOCX export')
