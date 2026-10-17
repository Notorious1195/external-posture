"""Condition-level findings and reproducible qualitative priority, not CVSS."""
from urllib.parse import urlsplit
import hashlib

def origin(url):
    u=urlsplit(url)
    return (u.scheme+'://'+u.netloc).rstrip('/') if u.scheme and u.netloc else url.lower().rstrip('/')

def classify(o):
    # 1..4 impact x likelihood, explicit bands. Indications capped at High.
    impact,likelihood=1,1;basis='Información de exposición; no se acredita una debilidad explotable.'
    control=o.get('control')
    if control=='V-03':impact,likelihood=4,3;basis='Configuración sensible accesible con firma corroborada; no se supone vigencia de secretos.'
    elif control=='V-02':impact,likelihood=3,3;basis='Referencia de código accesible corroborada; no acredita descarga del repositorio completo.'
    elif control=='T-03':impact,likelihood=3,3;basis='Contenido servido por HTTP sin redirección a HTTPS; impacto sujeto a datos y operaciones de la aplicación.'
    elif control in ('T-01','T-02'):impact,likelihood=3,2;basis='Debilidad comprobada en confianza o negociación TLS.'
    elif control in ('W-01','W-02','V-04','D-01','D-02'):
        minor=o.get('control_penalty',.25)<=.25
        impact,likelihood=(2,1) if minor else (2,2)
        basis='Deficiencia menor comprobada; impacto dependiente del contexto.' if minor else 'Deficiencia de configuración comprobada; no demuestra explotación.'
    elif o.get('zap_risk'):
        impact,likelihood={'high':(4,3),'medium':(3,2),'low':(2,1),'informational':(1,1)}.get(o['zap_risk'].lower(),(1,1))
        basis='Señal pasiva de ZAP; prioridad orientativa pendiente de validar impacto y aplicabilidad.'
    elif o['title']=='Servicios TCP accesibles':
        import re
        ports={int(x) for x in re.findall(r'(\d+)/tcp',o['fact'])}
        if ports & {21,23,3389,5900,1433,1521,3306,5432,6379,9200,27017}:impact,likelihood=3,3;basis='Servicio sensible accesible desde el punto de prueba; revisar necesidad y restricciones.'
    elif o['status']=='Indicio':impact,likelihood=2,2;basis='Señal automática pendiente de corroboración.'
    if o['title'] in ('Protección web detectada','Aplicación web identificada','Acceso web restringido') or o.get('condition')=='ZAP-10031' or o['title']=='Servicios TCP accesibles' and impact==1:
        return dict(risk='Informativo',risk_value=0,risk_impact=0,risk_likelihood=0,risk_reason='Observación de contexto o punto de revisión; no acredita una debilidad explotable.',risk_provisional=o['status']!='Confirmado',record_kind='Observación')
    value=impact*likelihood
    risk='Crítico' if value>=12 else 'Alto' if value>=8 else 'Medio' if value>=4 else 'Bajo'
    if o['status']=='Indicio' and risk=='Crítico':risk='Alto'
    return dict(risk=risk,risk_value=value,risk_impact=impact,risk_likelihood=likelihood,risk_reason=basis+' Matriz: impacto '+str(impact)+' × probabilidad '+str(likelihood)+' = '+str(value)+'.',risk_provisional=o['status']!='Confirmado')

def consolidate(observations):
    groups={}
    for o in observations:
        family=o.get('condition',o['title'].casefold())
        # Known equivalent conditions share a key, even across tools.
        key=(family,origin(o['asset']))
        if key not in groups:
            groups[key]={**o,'asset':origin(o['asset']),'affected_urls':[],'facts':[],'evidence':[],'legacy_ids':[],'source_titles':[]}
        g=groups[key]
        for field,values in [('affected_urls',o.get('affected_urls',[o['asset']])),('facts',[o['fact']]),('evidence',o['evidence']),('legacy_ids',[o['id']]),('source_titles',[o['title']])]:
            for value in values:
                if value not in g[field]:g[field].append(value)
        if o['status']=='Confirmado':
            g['status']='Confirmado';g['implication']=o['implication'];g['recommendation']=o['recommendation']
            if o.get('control'):g['control']=o['control'];g['control_penalty']=o.get('control_penalty')
        if o.get('password_form'):g['password_form']=True
        if o.get('zap_params'):g['zap_params']=sorted(set(g.get('zap_params',[]))|set(o['zap_params']))
        for field,single in (('zap_observed',None),('zap_alert_names','zap_alert_name'),('zap_descriptions','zap_description')):
            values=list(o.get(field) or ([o[single]] if single and o.get(single) else []))
            if values:g[field]=list(dict.fromkeys(g.get(field,[])+values))
    out=[]
    for i,g in enumerate(groups.values(),1):
        g['display_number']=i
        g['id']='HAL-'+hashlib.sha256((str(g.get('condition',g['title'].casefold()))+'|'+origin(g['asset'])).encode()).hexdigest()[:12].upper()
        g['fact']='\n'.join(g.pop('facts'))
        g.update(classify(g))
        from zap_catalog import entry
        if g.get('condition','').startswith('ZAP-'):
            rule=g['condition'][4:]
            title,description,recommendation=entry(rule.split('-')[0],rule)
            g['title']=title;g['recommendation']=recommendation
            g['catalog_description']=description
        elif g.get('control')=='W-01':g['title']='Ausencia de protección contra inclusión en marcos'
        elif g.get('control')=='W-02':g['title']='Ausencia de prevención de detección MIME'
        elif g.get('control')=='T-03':g['title']='Contenido servido por HTTP sin cifrado'
        g['record_kind']=g.get('record_kind','Hallazgo')
        if g.get('zap_rule')=='10031':
            hidden={'__VIEWSTATE','__EVENTVALIDATION','__VIEWSTATEGENERATOR'}
            params=g.get('zap_params',[])
            g['triage']={'prioritize':[x for x in params if x not in hidden],'hidden_fields':[x for x in params if x in hidden],'note':'Campos ocultos requieren revisión contextual; no se descartan como falsos positivos automáticamente.'}
        out.append(g)
    return out

VERIFICATION={
 'W-01':'Solicitar de nuevo las rutas afectadas y comprobar que cada respuesta HTML incluye X-Frame-Options DENY o SAMEORIGIN, o una CSP con frame-ancestors restrictivo.',
 'W-02':'Solicitar de nuevo las rutas afectadas y comprobar que las respuestas incluyen X-Content-Type-Options: nosniff y un Content-Type coherente con el recurso.',
 'T-03':'Solicitar la URL por HTTP y comprobar una redirección permanente a HTTPS; verificar que los formularios y recursos usan HTTPS y que el certificado es válido.',
 'T-01':'Repetir la conexión TLS y comprobar cadena de confianza completa, nombre coincidente y vigencia del certificado.',
 'T-02':'Repetir la enumeración de protocolos y cifrados (Nmap ssl-enum-ciphers) y comprobar que ya no se negocian los protocolos o cifrados señalados.',
 'D-01':'Consultar los registros TXT del dominio y comprobar que existe un único registro v=spf1 que termina en -all y declara todos los emisores legítimos.',
 'D-02':'Consultar _dmarc del dominio (y del dominio registrable si hay herencia) y comprobar una política p=reject o quarantine aplicada al 100 %.',
 'V-02':'Solicitar /.git/HEAD y una ruta inexistente de contraste; la ruta ya no debe devolver una firma de Git.',
 'V-03':'Solicitar /.env y una ruta inexistente de contraste; la ruta ya no debe devolver firmas de configuración. Revisar la rotación de secretos por separado.',
 'V-04':'Solicitar /phpinfo.php y comprobar que ya no devuelve la página de diagnóstico.',
}

def verification(item):
    """Check that would show the condition corrected, specific to the control or source."""
    if item.get('control') in VERIFICATION:return VERIFICATION[item['control']]
    if item.get('condition','').startswith('ZAP-'):return f"Repetir el análisis pasivo de ZAP sobre las {len(item.get('affected_urls',[])) or 1} ubicaciones afectadas y comprobar que la alerta «{item['title']}» ya no se registra."
    if item.get('title','').startswith('CVE reportada'):return 'Identificar el componente y su versión desde una fuente verificable y contrastarlos con el aviso de la CVE; la asociación pública no se cierra solo porque desaparezca de la fuente.'
    if item.get('title')=='Servicios TCP accesibles':return 'Repetir el sondeo de puertos y comprobar que solo permanecen accesibles los servicios necesarios.'
    return 'Repetir la comprobación específica en el activo afectado y conservar la respuesta fechada.'

def human_description(item):
    descriptions={
      'W-01':('La respuesta HTML comprobada no contiene una política restrictiva que impida que otro sitio la muestre dentro de un marco. Este resultado describe esa respuesta, no todas las páginas posibles.','Una página incrustada puede facilitar engaños sobre dónde hace clic una persona. No se ha demostrado que ese engaño permita ejecutar una acción sensible.','Definir Content-Security-Policy con frame-ancestors restrictivo o X-Frame-Options adecuado al uso legítimo; repetir la prueba en todas las rutas afectadas.'),
      'W-02':('La respuesta HTML comprobada no presenta X-Content-Type-Options con valor nosniff. Esa cabecera pide al navegador que respete el tipo de contenido declarado.','Su ausencia elimina una defensa frente a interpretaciones inesperadas de contenido. Por sí sola no demuestra ejecución de código ni un ataque exitoso.','Configurar X-Content-Type-Options: nosniff en las respuestas pertinentes y verificar que cada recurso declare un Content-Type correcto.'),
      'T-03':('La aplicación respondió con contenido por HTTP sin redirigir a HTTPS. HTTP transmite ese contenido sin la protección de cifrado que proporciona HTTPS.','Un tercero con capacidad de observar o alterar el trayecto de red podría leer o modificar tráfico. El impacto depende de los datos y operaciones presentes; no se ha acreditado interceptación en esta prueba.','Publicar la aplicación mediante HTTPS con certificado válido y redirigir HTTP a HTTPS. Comprobar navegación, recursos y formularios para evitar contenido mixto.'),
      'V-02':('Una ruta pública devolvió una firma de referencia de Git distinta de la respuesta a una ruta inexistente. No se demostró descarga completa del repositorio.','La referencia revela información sobre gestión de código y justifica comprobar que otros archivos del repositorio no sean públicos.','Impedir publicación del directorio .git y revisar el contenido del despliegue. Verificar de nuevo la ruta y su respuesta de contraste.'),
      'V-03':('Una ruta pública devolvió una firma de configuración de entorno corroborada frente a una ruta inexistente. Los valores sensibles no se conservan en el registro.','Estos archivos pueden contener información o secretos operativos. Su vigencia y alcance no se deducen de la firma; la exposición requiere tratamiento prioritario.','Retirar el archivo del directorio público, restringir acceso y revisar los secretos potencialmente expuestos para determinar si corresponde rotarlos.'),
      'D-01':('La política SPF publicada en el dominio evaluado no cumple completamente el criterio sintáctico de un único registro terminado en -all. La respuesta DNS es el soporte del resultado.','SPF permite declarar qué servidores pueden enviar correo en nombre del dominio. Esta comprobación no verifica todos sus mecanismos ni la entrega real de mensajes.','Revisar los emisores legítimos y publicar un único SPF coherente. Antes de endurecerlo, comprobar que incluya los servicios necesarios para evitar rechazos de correo legítimo.'),
      'D-02':('La política DMARC comprobada no cumple completamente el criterio de rechazo del modelo. La evidencia identifica si fue una política directa, heredada o ausente; un error DNS se conserva como pendiente.','DMARC comunica a los receptores cómo tratar mensajes que no alinean su autenticación con el dominio visible. Una publicación débil o ausente reduce esa directriz, sin demostrar que haya ocurrido suplantación.','Identificar el dominio y la política efectiva, revisar los emisores legítimos y ajustar p o sp según el alcance. Validar SPF/DKIM y alineación antes de desplegar rechazo.'),
    }
    if item.get('status')=='Confirmado' and item.get('control') in descriptions:
        result=descriptions[item['control']]
        if item.get('password_form'):return (result[0]+' Además, el HTML contiene un campo de contraseña en un formulario con destino HTTP. Se comprobó su configuración; no se enviaron credenciales ni se demostró su transmisión real.',result[1],result[2])
        return result
    if item.get('condition','').startswith('ZAP-') or any(t.startswith('ZAP:') for t in item.get('source_titles',[])):
        return ('El análisis pasivo de ZAP registró la condición «'+item['title']+'» en '+str(len(item.get('affected_urls',[])))+' ubicaciones del mismo origen. Se consolidó en una sola ficha, conservando las rutas y los registros originales.',item.get('catalog_description',item['implication'])+' La repercusión depende de las funciones y datos de la aplicación; el análisis pasivo no demuestra por sí solo una explotación.',item['recommendation'])
    return item['fact'],item['implication'],item['recommendation']
