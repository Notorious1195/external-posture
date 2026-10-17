"""Source-attributed, bounded public context, not attribution of compromise."""
import re
from redaction import clean

def extract_cves(value):
    found=set()
    def walk(v):
        if isinstance(v,dict):
            for key,item in v.items():
                found.update(re.findall(r'CVE-\d{4}-\d{4,}',str(key),re.I));walk(item)
        elif isinstance(v,list):
            for item in v:walk(item)
        elif isinstance(v,str):found.update(re.findall(r'CVE-\d{4}-\d{4,}',v,re.I))
    walk(value)
    return {c.upper() for c in found}

def source_summary(record):
    provider=record['provider'];obj=record.get('data') or {}
    row={k:record.get(k) for k in ('provider','target','status','queried_at_utc','error')}
    if record.get('status')!='OK':return row
    if provider=='VirusTotal':
        attrs=obj.get('data',{}).get('attributes',{})
        stats=attrs.get('last_analysis_stats',{})
        from datetime import datetime,timezone
        date=attrs.get('last_analysis_date')
        if isinstance(date,(int,float)):date=datetime.fromtimestamp(date,timezone.utc).isoformat()
        row.update(analysis_stats=stats,analysis_date=date,interpretation='Los conteos reflejan el análisis disponible; cero detecciones no acredita seguridad.')
    elif provider=='Shodan':
        row.update({k:obj.get(k) for k in ('asn','org','isp','hostnames','country_name','city','last_update')})
        row['cves']=sorted(extract_cves(obj))
    elif provider=='Censys':
        # Preserve only named metadata fields; avoid dumping full provider responses.
        def pick(value):
            out={}
            if isinstance(value,dict):
                for k,v in value.items():
                    if k in ('autonomous_system','location','dns','cloud','cloud_provider','cloud_region'):out[k]=v
                    elif isinstance(v,dict):out.update(pick(v))
            return out
        row['context']=pick(obj)
    elif provider=='RDAP':row.update(network_name=obj.get('name'),network_handle=obj.get('handle'),country=obj.get('country'),startAddress=obj.get('startAddress'),endAddress=obj.get('endAddress'))
    elif provider in ('URLhaus','ThreatFox'):row['query_status']=obj.get('query_status');row['interpretation']='Coincidencia o ausencia de registros según esta fuente; no acredita compromiso ni ausencia de actividad.'
    elif provider=='DNSDumpster':row['interpretation']='Fuente de inventario y contexto tecnológico; no demuestra titularidad de infraestructura compartida.'
    return clean(row)

def context(data):
    intel=data.get('public_intelligence',{})
    return {'sources':[source_summary(r) for r in intel.get('records',[])],'correlations':intel.get('correlations',[]),'kev_version':intel.get('kev_version')}
