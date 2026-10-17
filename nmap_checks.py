"""Nmap XML interpretation. Absence of an NSE result is unknown, not secure."""
import json,re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from posture import check

def tls_checks(result,url):
    try:root=ET.fromstring(result.get('output',''))
    except ET.ParseError:return check('T-02',url,evidence='XML TLS incompleto o inválido',source=result['tool'])
    scripts=root.findall('.//script[@id="ssl-enum-ciphers"]')
    protocols=[];weak=[]
    for script in scripts:
        for table in script.findall('table'):
            key=table.get('key','')
            if key.startswith(('SSL','TLS')):protocols.append(key)
        for cipher in script.findall('.//table[@key="ciphers"]/table'):
            fields={e.get('key'):e.text or '' for e in cipher.findall('elem')}
            name=fields.get('name','');strength=fields.get('strength','')
            if re.search(r'RC4|3DES|DES_CBC|EXPORT|NULL|MD5',name,re.I) or strength in ('C','D','E','F'):weak.append(name+' · '+strength)
        # Text fallback accepts cipher rows only; never the compressors block.
        if not script.findall('.//table[@key="ciphers"]/table'):
            for line in script.get('output','').splitlines():
                if re.match(r'\s*TLS_[A-Z0-9_]+',line) and re.search(r'RC4|3DES|DES_CBC|EXPORT|NULL|MD5| - [C-F]\s*$',line):weak.append(line.strip())
    protocols=sorted(set(protocols))
    evidence=json.dumps({'protocolos_observados':protocols,'cifrados_debiles_observados':weak,
        'nota':'No observado no significa deshabilitado. TLS 1.3 se contrasta con negociación directa; alcance limitado al NSE instalado.'},ensure_ascii=False)
    if not protocols:return check('T-02',url,evidence=evidence,source=result['tool'])
    old=any(p in ('SSLv2','SSLv3','TLSv1.0','TLSv1.1','TLSv1') for p in protocols)
    if old or weak:return check('T-02',url,'Evaluado',.6,evidence,result['tool'])
    # Negative conclusion only for the documented set this NSE enumerated successfully.
    if result['status']=='OK':return check('T-02',url,'Evaluado',0,evidence,result['tool'])
    return check('T-02',url,evidence=evidence,source=result['tool'])

def nse_observations(result,asset):
    try:root=ET.fromstring(result.get('output',''))
    except ET.ParseError:return []
    rows=[]
    for script in root.findall('.//script'):
        text=script.get('output','');sid=script.get('id','')
        if sid.startswith('http-vuln-') and re.search(r'\bVULNERABLE\b',text) and not re.search(r'NOT VULNERABLE',text):
            rows.append({'template':sid,'asset':asset,'fact':text,'source':result['tool'],'status':'Indicio'})
    return rows

def tls_summary(data):
    rows={}
    for c in data.get('nmap_tls_checks',[]):
        row=rows.setdefault(c['asset'],{'Activo':c['asset'],'TLS 1.0':'No observado','TLS 1.1':'No observado','TLS 1.2':'No observado','TLS 1.3':'No observado','Débiles':'No observado'})
        try:info=json.loads(c.get('evidence',''))
        except ValueError:continue
        for version in info.get('protocolos_observados',[]):
            label={'TLSv1':'TLS 1.0','TLSv1.0':'TLS 1.0','TLSv1.1':'TLS 1.1','TLSv1.2':'TLS 1.2','TLSv1.3':'TLS 1.3'}.get(version)
            if label:row[label]='Aceptado · NSE'
        if info.get('cifrados_debiles_observados'):row['Débiles']='Sí · revisar evidencia'
    for c in data.get('posture_probe',[]):
        match=re.search(r'protocolo=(TLSv1\.[0-3])',c.get('evidence',''))
        if match:
            row=rows.setdefault(c['asset'],{'Activo':c['asset'],'TLS 1.0':'No observado','TLS 1.1':'No observado','TLS 1.2':'No observado','TLS 1.3':'No observado','Débiles':'No observado'})
            row['TLS '+match.group(1).removeprefix('TLSv')]='Aceptado · negociación directa'
    return list(rows.values())
