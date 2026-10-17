import unittest,json
from finding_model import consolidate
from report_ai import validate_prose,observed_text,verified_reading,ungrounded
from posture import losses,explanation,calculate
from zap_catalog import entry
import test_v20
ZAP2={'pluginId':'2','alertRef':'2','name':'Private IP Disclosure','risk':'Low','confidence':'Medium','url':'http://t.example/Comments.aspx?id=2',
 'description':'A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the HTTP response body.','solution':'Remove it.','evidence':'10.10.150.200:48653'}
ZAP10061={'pluginId':'10061','alertRef':'10061','name':'X-AspNet-Version Response Header','risk':'Low','confidence':'High','url':'http://t.example/',
 'description':'Server leaks information via "X-AspNet-Version"/"X-AspNetMvc-Version" HTTP response header field(s).','solution':'Configure the server.','evidence':'2.0.50727'}
def finding(alert):
 from intelligence import build_observations
 d={'domain':'t.example','hosts':['t.example'],'subdomains':['t.example'],'resolved':['t.example'],'explicit_ips':[],'dns_ips':{},'ports':[],'scanned':[],'results':[],
    'historical_count':0,'visual_evidence':[],'visual_errors':[],'zap_reports':[{'url':'http://t.example','alerts':[alert],'status':'OK','crawler_complete':True,'passive_pending':0}]}
 obs,_=build_observations(d)
 return next(o for o in obs if o.get('zap_rule')==alert['pluginId'])
class V26(unittest.TestCase):
 def test_observed_value_reaches_finding_and_generic_examples_do_not(self):
  o=finding(ZAP2);text=observed_text(o)
  self.assertIn('10.10.150.200:48653',text);self.assertNotIn('ip-10-0-56-78',text);self.assertEqual(o['title'],'Divulgación de dirección IP privada')
 def test_rule_examples_rejected_real_values_accepted(self):
  o=finding(ZAP2)
  with self.assertRaisesRegex(ValueError,'ip-10-0-56-78'):validate_prose('Se observó el nombre de host interno ip-10-0-56-78 en el cuerpo de la respuesta de comentarios publicada.',o)
  self.assertTrue(validate_prose('Se observó la dirección privada 10.10.150.200 en el cuerpo de la respuesta de la página de comentarios.',o))
  o=finding(ZAP10061)
  with self.assertRaisesRegex(ValueError,'X-AspNetMvc-Version'):validate_prose('El servidor envía las cabeceras X-AspNet-Version y X-AspNetMvc-Version en las respuestas de la aplicación.',o)
  self.assertTrue(validate_prose('El servidor envía la cabecera X-AspNet-Version con el valor 2.0.50727 en las respuestas de la aplicación.',o))
 def test_dmarc_reading_and_dns_error(self):
  fact=json.dumps({'queried_domain':'a.example.com','organizational_domain':'example.com','effective_policy':'ausente','dns_responses':['status: NXDOMAIN','status: NXDOMAIN']})
  o={'id':'HAL-1','title':'Política DMARC','control':'D-02','status':'Confirmado','fact':fact,'implication':'i','recommendation':'r'}
  reading=verified_reading(o);self.assertIn('_dmarc.example.com',reading);self.assertIn('no es un error',reading)
  with self.assertRaisesRegex(ValueError,'Error DNS'):validate_prose('Aunque se observa un error DNS en la resolución, la política DMARC no está publicada para el dominio.',o)
  self.assertTrue(validate_prose('La consulta devolvió NXDOMAIN, sin error de resolución DNS: la política DMARC no existe para el dominio.',o))
 def test_spf_reading_ignores_other_txt(self):
  fact='a.example.com.10800INTXT"google-site-verification:abc"\na.example.com.10800INTXT"v=spf1 ~all"'
  self.assertIn('registros SPF (v=spf1): 1',verified_reading({'control':'D-01','fact':fact}))
 def test_csrf_terminology(self):
  with self.assertRaisesRegex(ValueError,'Terminología'):validate_prose('La cookie sin SameSite facilita ataques de fuerza de sitio cruzado contra los usuarios.',{'fact':'x','status':'Indicio'})
 def test_explanation_ranks_by_points_lost(self):
  d=test_v20.V20().fixture();p=calculate(d);l=losses(p)
  ordered=[t.lower() for t,_ in sorted(l.items(),key=lambda x:-x[1])][:3]
  text=explanation(d,p);self.assertIn('La nota se reduce principalmente por '+ordered[0],text)
 def test_upper_bound_equals_100_minus_losses(self):
  d=test_v20.V20().fixture();p=calculate(d)
  self.assertAlmostEqual(100-sum(losses(p).values()),p['interval'][1],places=1)
 def test_visual_kept_when_hal_title_is_retranslated(self):
  from evidence_capture import relink_visuals
  old=[{'id':'HAL-AAA','title':'Señal pasiva de seguridad web que requiere revisión','asset':'http://t','fact':'x'}]
  new=[{'id':'HAL-AAA','title':'Divulgación de dirección IP privada','asset':'http://t','fact':'x'}]
  v=[{'id':'VIS-1','observation_id':'HAL-AAA','render_version':20,'source':'vista de salida registrada de ZAP'}]
  relink_visuals(old,new,v);self.assertEqual(v[0]['observation_id'],'HAL-AAA')
 def test_internal_fields_scores_and_spf_contradiction(self):
  o={'fact':'x','status':'Indicio','title':'t'}
  with self.assertRaisesRegex(ValueError,'campos internos'):validate_prose('No se ha verificado una lectura (verified_reading vacío), por lo que es un indicio de la aplicación.',o)
  with self.assertRaisesRegex(ValueError,'dimensiones'):validate_prose('El servicio afecta a la dimensión W, cuyo cumplimiento es cero en la evaluación.',o)
  spf={'control':'D-01','status':'Confirmado','fact':'a.example.com.10800INTXT"google-site-verification:abc"\na.example.com.10800INTXT"v=spf1 ~all"','implication':'i','recommendation':'r'}
  with self.assertRaisesRegex(ValueError,'único registro SPF'):validate_prose('El registro termina en ~all, pero no se verifica si es el único registro publicado para el dominio.',spf)
  self.assertTrue(validate_prose('El dominio publica un único registro SPF que termina en ~all, lo que no cumple el criterio de terminar en -all.',spf))
 def test_csrf_only_for_csrf_conditions(self):
  w01={'title':'Ausencia de protección contra inclusión en marcos','control':'W-01','status':'Confirmado','fact':'headers','implication':'i','recommendation':'r'}
  with self.assertRaisesRegex(ValueError,'CSRF no corresponde'):validate_prose('La respuesta no incluye una directiva contra falsificación de solicitudes entre sitios en la página.',w01)
  csrf={'title':'Ausencia aparente de tokens contra solicitudes falsificadas','status':'Indicio','fact':'form'}
  self.assertTrue(validate_prose('Los formularios no muestran tokens contra falsificación de solicitudes entre sitios en la aplicación.',csrf))
 def test_standard_security_headers_can_be_recommended(self):
  o=finding(ZAP10061)
  self.assertTrue(validate_prose('Además de retirar la versión, conviene publicar X-Content-Type-Options y X-Frame-Options en las respuestas.',o))
 def test_catalog_private_ip(self):self.assertEqual(entry('2')[0],'Divulgación de dirección IP privada')
if __name__=='__main__':unittest.main(verbosity=2)
