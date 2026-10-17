"""Redaction at collection, model input, screenshot and report boundaries."""
import re
SENSITIVE={'authorization','proxy-authorization','cookie','set-cookie','x-api-key','auth-key','password','tbpassword','api_key','apikey','token','access_token','sessionid'}
def text(value):
    value=str(value)
    value=re.sub(r'("(?:set-cookie|authorization|cookie|x-api-key|auth-key|password|tbpassword|api_key|token)"\s*:\s*)"(?:[^"\\]|\\.)*"',r'\1"[REDACTADO]"',value,flags=re.I)
    value=re.sub(r'((?:ASP\.NET_SessionId|PHPSESSID|JSESSIONID|access_token|api_key|tbPassword)\s*=\s*)[^;\s&"<>]+',r'\1[REDACTADO]',value,flags=re.I)
    value=re.sub(r'(?im)^((?:Authorization|Cookie|Set-Cookie|X-API-Key|Auth-Key):)[^\r\n]*',r'\1 [REDACTADO]',value)
    value=re.sub(r'(<input\b[^>]*\btype=["\']password["\'][^>]*\bvalue=["\'])[^"\']*',r'\1[REDACTADO]',value,flags=re.I)
    return value

def clean(value):
    if isinstance(value,dict):return {k:('[REDACTADO]' if str(k).lower() in SENSITIVE else clean(v)) for k,v in value.items()}
    if isinstance(value,list):return [clean(v) for v in value]
    if isinstance(value,str):return text(value)
    return value

def utf8(value):
    if not isinstance(value,str):return value
    if any(marker in value for marker in ('Ã','Â','â€')):
        try:
            repaired=value.encode('latin1').decode('utf-8')
            if repaired.count('Ã')+repaired.count('Â')<value.count('Ã')+value.count('Â'):return repaired
        except (UnicodeError,ValueError):pass
    return value
