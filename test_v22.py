import json,unittest
from types import SimpleNamespace
from copy import deepcopy
from ip_discovery import discover,authorize,extract
from report_ai import approved_note
from test_v20 import V20
from posture import calculate
P=SimpleNamespace(write=lambda *a:None)
class V22(unittest.TestCase):
 def test_passive_ips_pagination_and_scope(self):
  d={'domain':'example.com','organization':'Empresa de prueba','dns_ips':{},'explicit_ips':[]};calls=[]
  def req(method,url,**kw):
   calls.append((url,kw))
   if 'shodan' in url:
    page=kw['params']['page'];return {'total':2,'matches':[{'ip_str':'8.8.8.8' if page==1 else '1.1.1.1','org':'Empresa de prueba','hostnames':[]}]}
   token=kw['json'].get('page_token');return {'result':{'hits':[{'host':{'ip':'8.8.8.8','dns':{'names':[]}}}],'next_page_token':''}}
  def rdap(*a):return {'provider':'RDAP','status':'OK','data':{'name':'Proveedor compartido'}}
  discover(d,{'keys':{'Shodan':'SENSITIVEKEY','Censys':'OTHERSECRET'},'ip_search_max_pages':3},P,req,rdap)
  self.assertEqual({r['ip'] for r in d['ip_candidates']},{'8.8.8.8','1.1.1.1'})
  self.assertTrue(all(not r['eligible'] for r in d['ip_candidates']));self.assertTrue(all(r['no_fqdn_observed'] for r in d['ip_candidates']))
  self.assertTrue(all(q['status']=='OK' for q in d['ip_discovery']['queries']))
  self.assertNotIn('SENSITIVEKEY',json.dumps(d));self.assertNotIn('OTHERSECRET',json.dumps(d))
  with self.assertRaises(ValueError):authorize(d,['8.8.8.8'],'')
  with self.assertRaises(ValueError):authorize(d,['9.9.9.9'],'Acta')
  authorize(d,['8.8.8.8','1.1.1.1'],'Alcance documentado de prueba');self.assertEqual(set(d['hosts']),{'8.8.8.8','1.1.1.1'})
 def test_limits_errors_and_nonpublic(self):
  d={'domain':'example.com','organization':'','dns_ips':{}}
  def req(*a,**k):return {'total':1000,'matches':[{'ip_str':'127.0.0.1'},{'ip_str':'8.8.8.8'}]}
  discover(d,{'keys':{'Shodan':'key'},'ip_search_max_pages':1},P,req,lambda *a:{'status':'ERROR','error':'RDAP unavailable'})
  self.assertEqual([r['ip'] for r in d['ip_candidates']],['8.8.8.8']);self.assertTrue(any(q['status']=='PARCIAL' for q in d['ip_discovery']['queries']))
  self.assertFalse(d['ip_candidates'][0]['eligible'])
 def test_censys_cursor(self):
  d={'domain':'example.com','dns_ips':{}};tokens=[]
  def req(*a,**k):
   t=k['json'].get('page_token','');tokens.append(t);return {'result':{'hits':[{'host':{'ip':'8.8.8.8'}}],'next_page_token':'next' if not t else ''}}
  discover(d,{'keys':{'Censys':'key'}},P,req,lambda *a:{'status':'OK','data':{}})
  self.assertEqual(tokens,['','next','','next'])
 def test_ptr_corroborates_without_authorizing(self):
  d={'domain':'example.com','dns_ips':{}}
  def remote(*args):return {'tool':'DNS inverso','status':'OK','output':json.dumps({'8.8.8.8':{'status':'OK','names':['host.example.com']}})}
  discover(d,{'keys':{'Shodan':'key'}},P,lambda *a,**k:{'total':1,'matches':[{'ip_str':'8.8.8.8','hostnames':[]}]},lambda *a:{'status':'OK','data':{}},remote)
  self.assertIn('host.example.com',d['ip_candidates'][0]['names']);self.assertFalse(d['ip_candidates'][0]['eligible'])
if __name__=='__main__':unittest.main(verbosity=2)
