from copy import deepcopy
from posture import calculate, checks_for, check
base={'domain':'example.com','hosts':['example.com'],'scanned':['example.com'],'ports':[],
 'results':[{'tool':'HTTPx Toolkit','output':'https://example.com [200]'}]}
base['manual_checks']=[check(c['control'],c['asset'],'Evaluado',0,'Validated external evidence') for c in checks_for(base) if c['control']!='V-01']
report={'url':'https://example.com','status':'PARCIAL','crawler_complete':False,'passive_pending':0,
 'alerts':[{'pluginId':'10038','risk':'Medium','confidence':'High','url':'https://example.com/a'}]}
base['zap_reports']=[report]
p=calculate(base)
assert p['score'] is not None and not p['complete']
c=next(c for c in p['checks'] if c['control']=='V-01')
assert c['penalty']==.6 and c['source'].startswith('ZAP pasivo')
repeated=deepcopy(base)
repeated['zap_reports'][0]['alerts']*=167
assert calculate(repeated)['observed_score']==p['observed_score']
other=deepcopy(base);other['zap_reports'][0]['alerts'].append({'pluginId':'OTHER','risk':'Medium','confidence':'High','url':'https://example.com/b'})
assert calculate(other)['observed_score']<p['observed_score']
false=deepcopy(base);false['zap_reports'][0]['alerts'][0]['confidence']='False Positive'
assert next(c for c in calculate(false)['checks'] if c['control']=='V-01')['status']=='No evaluado'
external=deepcopy(base);external['zap_reports'][0]['alerts'][0]['url']='https://other.com/a'
assert next(c for c in calculate(external)['checks'] if c['control']=='V-01')['status']=='No evaluado'
empty=deepcopy(base);empty['zap_reports'][0].update(status='OK',crawler_complete=True,alerts=[])
assert calculate(empty)['score']<100
print('PASS: conservative partial score reported; ZAP affects risk; 167 repeated alerts do not multiply penalty; distinct families contribute; false positives/out-of-scope excluded; no alerts does not prove safe')
