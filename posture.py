"""Experimental external posture model v14.0: rules, no LLM scoring."""
import hashlib
import json
import math
from collections import defaultdict
from datetime import datetime,timezone
from urllib.parse import urlsplit

VERSION='25.0'
DIMENSIONS={'V':('Exposiciones web específicas',.30),'E':('Exposición de servicios',.25),
            'W':('Controles de cabeceras web',.20),'T':('Cifrado y certificados',.15),'D':('Correo y DNS',.10)}
CONTROLS={
 'V-01':('V','Señales de riesgo web por aplicación',3,'ZAP pasivo: indicios, no vulnerabilidades confirmadas. Por tipo de regla y origen se toma el peor riesgo: Low=.20, Medium=.60, High=.90; confianza Low=.50, Medium=.75, High=1. Se combina 1−producto(1−p), máximo .95. Informativas y falsos positivos no penalizan; cero alertas no acredita seguridad. Peso interno 3 frente a 1 por archivo específico.'),
 'V-02':('V','Exposición de referencia Git',1,'Comprueba /.git/HEAD frente a ruta inexistente; no evalúa todas las rutas ni confirma descarga del repositorio completo.'),
 'V-03':('V','Exposición de configuración de entorno',1,'Comprueba /.env con firmas de configuración; valores sensibles no se almacenan. No afirma vigencia de credenciales.'),
 'V-04':('V','Exposición de diagnóstico PHP',1,'Comprueba /phpinfo.php por firma de diagnóstico; no determina explotabilidad de PHP.'),
 'E-01':('E','Servicios sensibles publicados',1,'Política: publicación de servicios administrativos/BD requiere revisión. 80/443 no se penalizan por estar abiertos.'),
 'W-01':('W','Política contra inclusión en marcos',1,'Se acepta X-Frame-Options DENY/SAMEORIGIN o CSP frame-ancestors restrictivo; ausencia: deficiencia menor.'),
 'W-02':('W','Prevención de detección MIME',1,'X-Content-Type-Options: nosniff; ausencia en HTML: deficiencia menor.'),
 'T-03':('T','Transporte web cifrado',1,'HTTP que sirve contenido sin redirigir a HTTPS: incumple, cero puntos. Puerto 80 usado solo para redirigir a HTTPS no se penaliza por estar abierto. Sin evidencia: cero acreditado, estado No evaluado.'),
 'T-01':('T','Certificado HTTPS verificable',1,'Cadena de confianza, vigencia y nombre verificados por TLS estándar; fallo de validación: importante. No cubre todos los protocolos/cifrados.'),
 'T-02':('T','Protocolos y cifrados TLS',1,'Nmap ssl-enum-ciphers: protocolos y cifrados observados. Ausencias no se interpretan como soporte deshabilitado. TLS 1.3 se contrasta con negociación directa.'),
 'D-01':('D','Política SPF del dominio evaluado',1,'Registro único con terminación -all: cumple el control sintáctico; ~all: menor; otros/ausencia: importante. No valida todos los mecanismos.'),
 'D-02':('D','Política DMARC del dominio evaluado',1,'Busca política DMARC directa y herencia hasta el dominio registrable; para herencia usa sp o p. reject con pct=100: cumple; quarantine: menor; none/ausencia: incumple. Ambigüedad o error DNS: No evaluado. No comprueba alineación, entrega ni políticas PSD.'),
 'D-03':('D','DKIM público',1,'Requiere selector público conocido y comprobación documentada; no se inventa un selector.'),
}
SENSITIVE={21,23,3389,5900,1433,1521,3306,5432,6379,9200,27017}

def check(control,asset,status='No evaluado',penalty=None,evidence='',source='Regla v15'):
    if status not in ('Evaluado','No evaluado','No aplica'): raise ValueError('Estado de control inválido')
    if status=='Evaluado' and (not isinstance(penalty,(int,float)) or not math.isfinite(penalty) or not 0<=penalty<=1): raise ValueError('Penalización inválida')
    if status!='Evaluado': penalty=None
    d,title,weight,reason=CONTROLS[control]
    return {'id':hashlib.sha256((control+'|'+asset).encode()).hexdigest()[:12], 'control':control,'dimension':d,
        'asset':asset,'title':title,'status':status,'penalty':penalty,'weight':weight,'evidence':evidence,'source':source,'reason':reason}

def checks_for(data,include_qwen=True):
    rows=[]
    for host in data.get('hosts',[]):
        ports=[p for p in data.get('ports',[]) if p.get('host')==host]
        if host in data.get('scanned',[]) or any(str(p.get('port','')).isdigit() and int(p['port']) in SENSITIVE for p in ports):
            sensitive=sorted({int(p['port']) for p in ports if str(p.get('port','')).isdigit() and int(p['port']) in SENSITIVE})
            unresolved=any(p.get('service') in ('tcpwrapped','unknown','') and str(p.get('port')) not in ('80','443') for p in ports)
            rows.append(check('E-01',host,'No evaluado' if unresolved and not sensitive else 'Evaluado',None if unresolved and not sensitive else .60 if sensitive else 0,
                'Nmap · '+host+'; TCP top100; sensibles observados: '+(', '.join(map(str,sensitive)) or 'ninguno entre los puertos examinados')))
        else: rows.append(check('E-01',host))
        if not any(r.get('tool')=='HTTPx Toolkit' and r.get('output','').strip() for r in data.get('results',[])):
            rows.append(check('V-01',host))
    urls=set()
    for r in data.get('results',[]):
        if r.get('tool')=='HTTPx Toolkit':
            for line in r.get('output','').splitlines():
                token=line.split()[0] if line.split() else ''
                if token.startswith(('http://','https://')): urls.add(token)
    for url in sorted(urls):
        rows.extend([check('W-01',url),check('W-02',url),check('V-01',url),check('V-02',url),check('V-03',url),check('V-04',url)])
        rows.extend([check('T-03',url),check('T-01',url),check('T-02',url)])
    rows.extend(check(c,data['domain']) for c in ('D-01','D-02','D-03'))
    def normalized(items):
        result={}
        for x in items:
            if x.get('control') not in CONTROLS: continue
            status=x.get('status','No evaluado'); penalty=x.get('penalty'); evidence=x.get('evidence','')
            if x['control']=='T-01' and 'unable to get local issuer certificate' in evidence:
                status='No evaluado';penalty=None;evidence+=' · Requiere contraste del almacén CA; no se atribuye automáticamente al servidor.'
            c=check(x['control'],x['asset'],status,penalty,evidence,x.get('source','Importado'))
            if c['status']=='No aplica' and not c['evidence'].strip(): raise ValueError('No aplica requiere justificación')
            result[(c['control'],c['asset'])]=c
        return result
    automatic=normalized(data.get('posture_probe',[]))
    tls=defaultdict(list)
    for c in data.get('nmap_tls_checks',[]):tls[(c['control'],c['asset'])].append(c)
    for k,items in tls.items():
        measured=[c for c in items if c.get('status')=='Evaluado']
        bad=[c for c in measured if c.get('penalty',0)>0]
        selected=max(bad,key=lambda c:c['penalty']) if bad else (measured[0] if len(measured)==len(items) and measured else items[0])
        selected=dict(selected)
        if not bad and len(measured)!=len(items):selected['status']='No evaluado';selected['penalty']=None
        selected['evidence']='\n'.join(c.get('source','')+' · '+c.get('evidence','') for c in items)
        automatic[k]=selected
    # A route repeated 167 times is still one risk family for that origin.
    for report in data.get('zap_reports',[]):
        from access_policy import unavailable
        if report.get('application_evaluable') is False or unavailable(data,report.get('url','')):continue
        asset=report.get('url','').rstrip('/')
        target=next((u for u in urls if u.rstrip('/')==asset),None)
        if not target: continue
        families={}
        for alert in report.get('alerts',[]):
            rule=str(alert.get('pluginId',''))
            if rule in ('10020','10021'): continue  # Already assessed by W-01/W-02.
            location=urlsplit(alert.get('url',''))
            origin=urlsplit(target)
            if (location.scheme,location.netloc)!=(origin.scheme,origin.netloc): continue
            confidence=str(alert.get('confidence','')).lower()
            risk=str(alert.get('risk','')).lower()
            if confidence in ('false positive','0') or risk in ('informational','info','0'): continue
            severity={'low':.20,'medium':.60,'high':.90}.get(risk)
            certainty={'low':.50,'medium':.75,'high':1.,'confirmed':1.}.get(confidence)
            if severity is None or certainty is None or not rule: continue
            families[rule]=max(families.get(rule,0),severity*certainty)
        evidence=json.dumps({'source':'ZAP pasivo','risk_families':families,
            'raw_alerts':len(report.get('alerts',[])), 'crawler_complete':report.get('crawler_complete',False),
            'status':report.get('status'),'interpretation':'Indicios por validar; no confirmación de explotación'},ensure_ascii=False)
        if families:
            automatic[('V-01',target)]=check('V-01',target,'Evaluado',min(.95,1-math.prod(1-p for p in families.values())),evidence,'ZAP pasivo · indicios')
        else:
            automatic[('V-01',target)]=check('V-01',target,evidence=evidence,source='ZAP pasivo · alcance insuficiente para acreditar seguridad')
    manual=normalized(data.get('manual_checks',[]))
    baseline=[manual.get((r['control'],r['asset']),automatic.get((r['control'],r['asset']),r)) for r in rows]
    from access_policy import unavailable
    for c in baseline:
        if c['dimension'] in ('V','W') and unavailable(data,c['asset']) and (c['control'],c['asset']) not in manual:
            c.update(status='No evaluado',penalty=None,evidence='Acceso restringido o no comprobado; no se evalúa la aplicación a partir de una página de bloqueo.')
    return baseline

def category(score):
    return 'Favorable' if score>=85 else 'Moderada' if score>=65 else 'Deficiente' if score>=40 else 'Crítica'

def calculate(data):
    rows=checks_for(data);dims=[];warnings=[]
    for d,(name,weight) in DIMENSIONS.items():
        all_rows=[r for r in rows if r['dimension']==d]
        applicable=[r for r in all_rows if r['status']!='No aplica']
        groups=defaultdict(list)
        for r in applicable:groups[r['control']].append(r)
        def grade(upper=False):
            values=[]
            for control,items in groups.items():
                credits=[1-r['penalty'] if r['status']=='Evaluado' else (1 if upper else 0) for r in items]
                values.append((CONTROLS[control][2],sum(credits)/len(credits)))
            return 100*sum(w*c for w,c in values)/sum(w for w,c in values) if values else None
        done=sum(r['status']=='Evaluado' for r in applicable)
        passed=sum(r['status']=='Evaluado' and r['penalty']==0 for r in applicable)
        dims.append({'dimension':d,'name':name,'weight':weight,'score':grade(),
            'lower':grade(),'upper':grade(True),'done':done,'passed':passed,
            'partial':sum(r['status']=='Evaluado' and 0<r['penalty']<1 for r in applicable),
            'failed':sum(r['status']=='Evaluado' and r['penalty']==1 for r in applicable),
            'unknown':len(applicable)-done,'not_applicable':len(all_rows)-len(applicable),
            'planned':len(applicable),'coverage':100*done/len(applicable) if applicable else 0})
    active=[d for d in dims if d['score'] is not None]
    total_weight=sum(d['weight'] for d in active)
    score=sum(d['weight']*d['score'] for d in active)/total_weight if total_weight else None
    upper=sum(d['weight']*d['upper'] for d in active)/total_weight if total_weight else None
    applicable=[r for r in rows if r['status']!='No aplica'];done=sum(r['status']=='Evaluado' for r in applicable)
    coverage=100*done/len(applicable) if applicable else 0
    web_partial=any(r.get('status')!='OK' or not r.get('crawler_complete') or r.get('passive_pending',-1)!=0 for r in data.get('zap_reports',[]))
    complete=bool(applicable) and done==len(applicable) and not web_partial
    alerts=[r for r in rows if r['status']=='Evaluado' and r.get('penalty')==1]
    if alerts:warnings.append('Existen incumplimientos confirmados de controles; no equivalen automáticamente a vulnerabilidades críticas.')
    if not complete:warnings.append('Puntaje conservador de cumplimiento acreditado: pendientes aportan cero, pero conservan el estado No evaluado. No demuestra que todos los pendientes hayan fallado.')
    if web_partial:warnings.append('Hay recorridos ZAP parciales; sus indicios se conservan y la cobertura permanece incompleta.')
    if any(d['not_applicable'] for d in dims):warnings.append('Controles No aplica excluidos únicamente con justificación documentada.')
    return {'version':VERSION,'score':round(score,2) if score is not None else None,
        'category':('No concluyente' if coverage<70 else category(score)) if score is not None else 'Sin controles aplicables',
        'observed_category':category(score) if score is not None else 'Sin datos',
        'observed_score':round(score,2) if score is not None else None,
        'coverage':round(coverage,2),'interval':[round(score,2),round(upper,2)] if score is not None else [0,100],
        'complete':complete,'dimensions':dims,'checks':rows,'critical_alerts':alerts,'warnings':warnings,
        'score_type':'Cumplimiento acreditado conservador',
        'methodology':'Crédito=1−penalización para Evaluado; crédito=0 para No evaluado. No aplica justificado se excluye. S_d=100·Σw_c·promedio(crédito por activo)/Σw_c. P=Σw_d·S_d/Σw_d para dimensiones aplicables; controles vacíos no acreditan cumplimiento. Pesos V/E/W/T/D=30/25/20/15/10; peso interno V-01=3, demás=1. Ejemplo ilustrativo, no resultado de esta evaluación: en D, con tres controles de peso igual, uno plenamente cumplido y dos pendientes darían 33,33. Rango superior solo describe la hipótesis de cumplimiento de pendientes. ZAP indica riesgo potencial, no explotación confirmada. Experimental.',
        'scope':'Cumplimiento de controles externos y evidencia disponible; no probabilidad de ataque ni evaluación interna.'}

def snapshot(data):
    from pathlib import Path
    p=calculate(data);folder=Path('resultados')/'historico'/data['domain'];folder.mkdir(parents=True,exist_ok=True)
    entry={'date':datetime.now(timezone.utc).isoformat(),'domain':data['domain'],'posture':p,
        'hosts':data.get('hosts',[]),'nmap_top_ports':data.get('nmap_top_ports',100)}
    path=folder/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')+'.json')
    path.write_text(json.dumps(entry,ensure_ascii=False,indent=2),encoding='utf-8')
    return entry

def history(domain):
    from pathlib import Path
    rows=[]
    for path in sorted((Path('resultados')/'historico'/domain).glob('*.json')):
        try: rows.append(json.loads(path.read_text(encoding='utf-8')))
        except (ValueError,OSError): pass
    return rows


def es_num(value,decimals=None):
    """Spanish decimal comma for figures shown to readers; the JSON keeps numeric values."""
    text=f"{value:.{decimals}f}" if decimals is not None else str(round(value,2))
    return text.replace('.',',')

def sentence_case(title):
    # Lowercase for running text, but keep acronyms such as DMARC, SPF, MIME or TLS.
    return ' '.join(w if len(w)>1 and w.isupper() else w.lower() for w in title.split())

def losses(p):
    """Points of the global score lost to evaluated penalties, per control title. Pending controls are not failures."""
    active={d['dimension']:d['weight'] for d in p['dimensions'] if d['score'] is not None}
    total=sum(active.values());result=defaultdict(float)
    for d in active:
        rows=[r for r in p['checks'] if r['dimension']==d and r['status']!='No aplica']
        controls=defaultdict(list)
        for r in rows:controls[r['control']].append(r)
        weights=sum(CONTROLS[c][2] for c in controls)
        for control,items in controls.items():
            penalty=sum(r['penalty'] for r in items if r['status']=='Evaluado')/len(items)
            if penalty>0:result[items[0]['title']]+=100*active[d]/total*CONTROLS[control][2]/weights*penalty
    return dict(result)

def explanation(data,p=None):
    p=p or calculate(data)
    if p['score'] is None:return 'Aún no hay controles aplicables con los que calcular el cumplimiento acreditado.'
    failures=sorted(losses(p).items(),key=lambda x:-x[1])
    text=f"El cumplimiento acreditado es {es_num(p['score'])}/100, con {es_num(p['coverage'])}% de las comprobaciones completadas. "
    text+=('La nota se reduce principalmente por '+'; '.join(f"{sentence_case(title)} (−{es_num(value,2)} puntos)" for title,value in failures[:3])+'. ' if failures else 'No se documentaron deficiencias en los controles completados. ')
    if not p['complete']:text+='Las verificaciones pendientes aportan cero crédito; el acceso restringido y los datos incompletos limitan la evaluación y no equivalen a fallas comprobadas. '
    if p['category']=='No concluyente':text+='La cobertura disponible no permite asignar una clasificación global concluyente.'
    return text.strip()
