"""Offline PSL extraction. No guessed last-two-label ownership."""
import tldextract
extract=tldextract.TLDExtract(suffix_list_urls=(),include_psl_private_domains=False)
def registrable_domain(domain):
    result=extract(domain.lower().rstrip('.'))
    if not result.suffix or not result.domain:raise ValueError('Dominio registrable no identificado con la PSL local')
    return result.top_domain_under_public_suffix

def dmarc_policy(domain,organizational,lookup):
    """Check exact policy first, then DNS ancestors to organizational boundary.
    Conservative subset: ambiguous records/errors remain unknown; PSD not scored.
    """
    names=[];current=domain
    while True:
        names.append(current)
        if current==organizational:break
        if not current.endswith('.'+organizational):raise ValueError('Límite organizacional inválido')
        current=current.split('.',1)[1]
    logs=[]
    for name in names:
        records,raw=lookup('_dmarc.'+name);logs.append(raw)
        dm=[x for x in records if x.lower().startswith('v=dmarc1')]
        if not dm:continue
        if len(dm)!=1:raise ValueError('DMARC ambiguo: varios registros en '+name)
        tags={}
        for part in dm[0].split(';'):
            if '=' in part:
                k,v=part.strip().lower().split('=',1)
                if k in tags:raise ValueError('DMARC ambiguo: etiqueta duplicada '+k)
                tags[k]=v
        if tags.get('p') not in ('reject','quarantine','none'):raise ValueError('DMARC sin política p válida')
        policy=tags.get('sp',tags['p']) if name!=domain else tags['p']
        if policy not in ('reject','quarantine','none'):raise ValueError('DMARC sp inválida')
        pct=tags.get('pct','100')
        if not pct.isdigit() or not 0<=int(pct)<=100:raise ValueError('DMARC pct inválido')
        penalty=0 if policy=='reject' and int(pct)==100 else .25 if policy in ('reject','quarantine') else 1
        return penalty,{'queried_domain':domain,'policy_domain':name,'inherited':name!=domain,'effective_policy':policy,'pct':int(pct),'dns_responses':logs,'limits':'Comprobación de publicación; no verifica alineación ni entrega de correo; no aplica políticas PSD.'}
    return 1,{'queried_domain':domain,'organizational_domain':organizational,'effective_policy':'ausente','dns_responses':logs}
