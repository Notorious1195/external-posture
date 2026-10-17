"""Version 25: Qwen-only guided external assessment."""
import base64
import hashlib
import json
import secrets
import os
from public_sources import PROVIDERS, ENV_KEYS, record, enrich, kev_catalog, refresh_kev
from posture import calculate, check, snapshot, history
from posture_probe import collect as collect_posture
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
import streamlit as st
from PIL import Image
from backend import (domain_ok, probe_host, run_tool, qwen, recognize, evaluate_inventory,
                     generate_narrative, save_checkpoint)
from assets import public_ips, dashboard_data, dns_ip_map
from intelligence import build_observations, grounded_sections
from docx_report import report_docx

st.set_page_config(page_title="Superficie externa · v25", layout="wide")
st.markdown('''<style>
.stApp{background:#0b1119;color:#e5edf5}
[data-testid="stSidebar"]{background:#101923;border-right:1px solid #334657}
h1,h2,h3{color:#dfffea}
[data-testid="stCaptionContainer"]{color:#aebed0}
[data-testid="stMetric"]{background:#14212d;border:1px solid #375066;padding:16px;border-radius:10px}
[data-testid="stMetricValue"]{color:#72f3ad}
.stButton button{background:#182738;color:#e5edf5;border:1px solid #50677c}
.stButton button:hover{background:#263e52;color:#a5ffd0;border-color:#72f3ad}
.stButton button[kind="primary"]{background:#72f3ad;color:#082015;border:1px solid #72f3ad;font-weight:700}
.stButton button:disabled{background:#17212b;color:#8291a2;border-color:#344150}
[data-testid="stSidebar"] .stButton button{width:100%;text-align:left;background:#182738;color:#e5edf5}
[data-testid="stSidebar"] .stButton button[kind="primary"]{background:#214b39;color:#b9ffdb;border:2px solid #72f3ad}
[data-baseweb="tab-list"]{gap:8px;flex-wrap:wrap;background:#101923;padding:10px;border:1px solid #344b61;border-radius:8px}
[data-baseweb="tab"]{background:#1b2b3b;color:#d7e5f3;border:1px solid #50677c;border-radius:6px;padding:10px 16px;height:auto}
[data-baseweb="tab"][aria-selected="true"]{background:#214b39;color:#b9ffdb;border:2px solid #72f3ad;font-weight:700}
[data-baseweb="tab-highlight"]{background:#72f3ad}
[data-baseweb="tab"]:focus-visible,.stButton button:focus-visible{outline:3px solid #9cf8c5;outline-offset:3px}
.block-container{padding-top:2rem} </style>''', unsafe_allow_html=True)
PAGES = ["Proyecto", "Alcance", "Kali SSH", "Modelo de IA", "APIs y fuentes públicas", "Reconocimiento", "Inventario externo",
         "Evaluación completa", "Dashboards", "Postura externa", "Hallazgos y evidencias", "Informe"]
for key,value in {"page":0,"scan":None,"scope":None,"model_ok":False}.items():
    if key not in st.session_state: st.session_state[key]=value

def go(index):
    st.session_state.page=index
    st.rerun()

def nav(ready=True):
    a,b=st.columns([1,1])
    if a.button("← Anterior",disabled=st.session_state.page==0): go(st.session_state.page-1)
    if b.button("Siguiente →",disabled=not ready or st.session_state.page==len(PAGES)-1,type="primary"):
        go(st.session_state.page+1)

def rebuild(data):
    from public_sources import correlate_cached
    from access_policy import normalize
    normalize(data)
    correlate_cached(data)
    data["organization"]=st.session_state.get("organization") or data.get("organization") or data["domain"]
    data["project_name"]=st.session_state.get("project_name") or data.get("project_name") or "Evaluación de postura externa"
    data.setdefault("explicit_ips",[])
    data["explicit_ips"] = public_ips("\n".join(data["explicit_ips"]),limit=65536)
    for h in data.get("resolved",[]):
        if domain_ok(h) != data["domain"] and not h.endswith("."+data["domain"]):
            raise ValueError("Nombre resuelto fuera del alcance autorizado")
    if "dns_ips" not in data:
        dns=next((r.get("output","") for r in data.get("results",[]) if r["tool"]=="DNSx"),"")
        data["dns_ips"]=dns_ip_map(dns,set(data.get("subdomains",[])))
    for key,value in {"ports":[],"scanned":[],"hosts":[],"resolved":[],"visual_evidence":[],"visual_errors":[],"historical_count":0}.items():
        data.setdefault(key,value)
    data["hosts"] = sorted(set(data["resolved"]) | set(data["explicit_ips"]))
    previous=list(data.get("observations",[]))
    data["observations"],data["coverage"]=build_observations(data)
    from evidence_capture import relink_visuals
    relink_visuals(previous,data["observations"],data.get("visual_evidence",[]))
    assessment,actions=grounded_sections(data,data["observations"],data["coverage"])
    data.setdefault("narrative",{})
    data["narrative"].update(assessment=assessment,actions=actions)
    return data

with st.sidebar:
    st.title("Superficie externa")
    st.caption("Versión 25 · Evaluación guiada")
    for index,label in enumerate(PAGES):
        if st.button(("● " if index==st.session_state.page else "")+label,key="menu_"+str(index),
                     type="primary" if index==st.session_state.page else "secondary",use_container_width=True): go(index)
    st.divider()
    st.caption("SSH: "+("conectado" if "connection" in st.session_state else "pendiente"))
    st.caption("Modelo: "+("verificado" if st.session_state.model_ok else "sin IA · catálogo" if st.session_state.get("without_ai") else "pendiente"))
page=st.session_state.page
st.caption("PROYECTO / "+PAGES[page].upper())
st.title(PAGES[page])
st.progress(page/(len(PAGES)-1))
data=st.session_state.scan

if page==0:
    st.write("Construye el inventario en reconocimiento, revisa su alcance y evalúa todos sus activos elegibles. Los dashboards y el informe usan los resultados conservados.")
    st.text_input("Nombre del proyecto",key="project_name",value=(data or {}).get("project_name","Evaluación de postura externa"))
    st.text_input("Organización",key="organization",value=(data or {}).get("organization",""))
    upload=st.file_uploader("Continuar desde un JSON de evidencias o checkpoint",type="json")
    if st.button("Cargar proyecto",disabled=upload is None):
        try:
            loaded=json.load(upload)
            loaded["domain"]=domain_ok(loaded["domain"])
            if not isinstance(loaded.get("results"),list): raise ValueError("Falta lista de resultados")
            st.session_state.scan=rebuild(loaded)
            st.success("Proyecto cargado. Puedes revisar inventario, dashboards e informe.")
        except Exception as exc: st.error(str(exc))
    nav()
elif page==1:
    with st.form("scope_form"):
        domain=st.text_input("Dominio raíz autorizado",value=(st.session_state.scope or {}).get("domain",""))
        ips=st.text_area("IPv4 públicas o CIDR propios autorizados (opcional)",value=(st.session_state.scope or {}).get("ip_text",""))
        st.caption("Las IPs obtenidas por DNS se registran como relaciones; no se asume que sus bloques sean propios.")
        authorized=st.checkbox("El dominio, sus subdominios y los rangos declarados están autorizados para esta evaluación")
        if st.form_submit_button("Guardar alcance",type="primary"):
            try:
                if not authorized: raise ValueError("Confirma el alcance autorizado")
                scope={"domain":domain_ok(domain),"ips":public_ips(ips,limit=65536),"ip_text":ips}
                if st.session_state.scope and st.session_state.scope!=scope:
                    st.session_state.scan=None
                    st.info("Cambió el alcance: vuelve a ejecutar el reconocimiento para construir el nuevo inventario.")
                st.session_state.scope=scope
                st.success("Alcance guardado")
            except Exception as exc: st.error(str(exc))
    nav(st.session_state.scope is not None)
elif page==2:
    a,b=st.columns(2)
    host=a.text_input("IP o nombre de Kali",key="kali_host")
    port=a.number_input("Puerto SSH",1,65535,22,key="kali_port")
    user=b.text_input("Usuario",key="kali_user")
    password=b.text_input("Contraseña",type="password",key="kali_password")
    if st.button("Obtener huella SSH"):
        try:
            st.session_state.proposed=(host,int(port),probe_host(host,int(port)))
        except Exception as exc: st.error(str(exc))
    if st.session_state.get("proposed"):
        h,p,fp=st.session_state.proposed
        st.code(fp)
        st.caption("Comprueba la huella en Kali con ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256")
        if st.button("Reconozco esta Kali · conectar",type="primary"):
            try:
                if (host,int(port))!=(h,p): raise ValueError("Cambió el destino; obtén su huella nuevamente")
                st.session_state.connection={"host":h,"port":p,"user":user,"password":password,"fingerprint":fp}
                result=run_tool("SSH",["nmap","--version"],20)
                if result["status"]!="OK":
                    del st.session_state.connection
                    raise ValueError(result["stderr"])
                st.success("Conexión establecida")
            except Exception as exc: st.error(str(exc))
    nav("connection" in st.session_state)
elif page==3:
    previous=st.session_state.get("model_config",{})
    if previous.get("provider", "local") != "local":
        previous={}
        st.session_state.pop("model_config", None)
        st.session_state.model_ok=False
    st.write("Qwen mediante LM Studio")
    url=st.text_input("URL de LM Studio",value=previous.get("url","http://127.0.0.1:1234"),key="base_local")
    from llm_client import models as lm_models, prepare as lm_prepare, workers_for, ModelError
    if st.button("Detectar modelos Qwen"):
        try:
            st.session_state.lm_models=[m for m in lm_models({"url":url.strip()}) if "qwen" in m["id"].lower()]
            if not st.session_state.lm_models:st.warning("El servidor responde, pero no publica modelos Qwen.")
        except ModelError as exc:
            st.session_state.lm_models=[];st.error(str(exc))
    found=st.session_state.get("lm_models") or []
    if found:
        ids=[m["id"] for m in found];loaded=[m["id"] for m in found if m["state"]=="loaded"]
        default=previous.get("id") if previous.get("id") in ids else (loaded or ids)[0]
        def label(model_id):
            m=next(m for m in found if m["id"]==model_id)
            if m["state"]=="loaded":return f"{model_id} · cargado"+(f", contexto {m['context']}" if m["context"] else "")
            return model_id+(" · no cargado" if m["state"] else "")
        model=st.selectbox("ID del modelo Qwen",ids,index=ids.index(default),key="model_pick",format_func=label)
    else:
        model=st.text_input("ID del modelo Qwen",value=previous.get("id",""),key="model_local",help="Copia el identificador de Qwen cargado en LM Studio o pulsa Detectar modelos Qwen. Debe contener Qwen; no se admiten otras familias.")
    api_key=""
    config={"provider":"local","url":url.strip(),"id":model.strip(),"api_key":api_key}
    signature=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()
    if signature!=st.session_state.get("tested_model_signature"):st.session_state.model_ok=False
    st.caption("Qwen redacta el informe con el contexto y las evidencias. La puntuación y el riesgo se calculan con las mismas reglas. La revisión posterior con Claude será manual.")
    if st.button("Probar modelo",disabled=not model.strip()):
        try:
            st.session_state.model_config=config
            info=lm_prepare(config)
            answer=qwen([{"role":"system","content":"Responde exactamente con la palabra OK."},{"role":"user","content":"Comprobación de conexión"}])
            st.session_state.model_ok=True;st.session_state.without_ai=False
            st.session_state.tested_model_signature=signature
            st.success("Conexión establecida"+(f" · ventana de contexto cargada: {info['context']} tokens · {workers_for(info['context'],3)} redacciones en paralelo" if info.get("context") else ""))
            for warning in info["warnings"]:st.warning(warning)
        except Exception as exc:
            st.session_state.model_ok=False
            st.error(str(exc))
    st.divider()
    # The model only drafts the report; reconnaissance, evaluation and scoring never depend on it.
    st.caption("Sin LM Studio también se puede evaluar: la puntuación y los riesgos no usan el modelo y el informe se redacta con el catálogo y los datos registrados.")
    if st.button("Continuar sin IA"):
        st.session_state.pop("model_config",None);st.session_state.model_ok=False;st.session_state.without_ai=True
        go(page+1)
    nav(st.session_state.model_ok or st.session_state.get("without_ai",False))
elif page==4:
    st.write("Fuentes públicas automáticas. Las claves se conservan solo en esta sesión o se leen de variables de entorno; no se guardan en los resultados.")
    previous=st.session_state.get("api_config",{})
    abuse_via_kali=dnsdumpster_enabled=ct=True
    enabled=list(PROVIDERS)
    st.caption("Certificados públicos y fuentes API se consultan automáticamente. Completa las credenciales y comprueba la conexión.")
    keys={}
    for provider,env in ENV_KEYS.items():
        keys[provider]=st.text_input(provider+" · "+env,type="password",value=previous.get("keys",{}).get(provider,os.environ.get(env,"")),key="credential_"+provider)
    st.caption("URLhaus y ThreatFox pueden usar la misma Auth-Key. EPSS y RDAP no necesitan clave. VirusTotal requiere una licencia compatible con el uso previsto.")
    ip_pages=st.number_input('Máximo de páginas por búsqueda de IPs en Shodan/Censys',min_value=1,max_value=100,value=int(previous.get('ip_search_max_pages',5)),step=1)
    st.caption('Un límite o una cuota detenida se registra como búsqueda parcial; no es una muestra de los objetivos elegibles.')
    if st.button("Aplicar configuración de fuentes",type="primary"):
        st.session_state.api_config={"enabled":enabled,"keys":keys,"ct_enabled":ct,"abuse_via_kali":abuse_via_kali,"dnsdumpster_enabled":dnsdumpster_enabled,"ip_search_max_pages":int(ip_pages)}
        st.success("Configuración aplicada a esta sesión")
    provider=st.selectbox("Fuente para probar conexión",PROVIDERS)
    target=st.text_input("Objetivo de consulta de prueba (IP para Shodan/Censys; CVE para EPSS; dominio/IP para otras)",value="")
    if st.button("Probar consulta",disabled=not target):
        import ipaddress
        try: ipaddress.ip_address(target);is_ip=True
        except ValueError:is_ip=False
        if provider in ("URLhaus","ThreatFox") and abuse_via_kali:
            if "connection" not in st.session_state:
                st.error("Conecta Kali por SSH antes de probar estas APIs")
                r={"provider":provider,"target":target,"status":"ERROR","queried_at_utc":"","error":"SSH pendiente"}
            else:
                from public_sources import record_from_kali
                r=record_from_kali(provider,target.strip(),keys.get(provider,""),run_tool)
        else:r=record(provider,target.strip(),keys.get(provider,""),is_ip)
        if r.get("diagnostic"):
            with st.expander("Diagnóstico de conexión desde Kali"):st.json(r["diagnostic"])
        st.write({k:r[k] for k in ("provider","target","status","queried_at_utc")})
        if r.get("error"):st.error(r["error"])
        else:st.success("Consulta respondida. No implica acceso a todos los endpoints ni cuota ilimitada.")
    catalog=kev_catalog()
    st.info(f"CISA KEV local: {catalog['catalogVersion']} · {catalog['count']} CVE")
    uploaded=st.file_uploader("Actualizar catálogo KEV con JSON oficial",type="json",key="kev_upload")
    if st.button("Importar catálogo",disabled=uploaded is None):
        try:
            from pathlib import Path
            obj=json.load(uploaded)
            if not isinstance(obj.get("vulnerabilities"),list) or obj.get("count")!=len(obj["vulnerabilities"]):raise ValueError("Catálogo inválido")
            Path(__file__).with_name("data").joinpath("known_exploited_vulnerabilities.json").write_text(json.dumps(obj,ensure_ascii=False),encoding="utf-8")
            st.success("Catálogo actualizado")
        except Exception as exc:st.error(str(exc))
    if st.button("Actualizar KEV desde repositorio oficial CISA"):
        try:obj=refresh_kev();st.success("KEV actualizado: "+obj["catalogVersion"])
        except Exception as exc:st.error(str(exc))
    nav()
elif page==5:
    st.write("Subfinder, certificados públicos y fuentes históricas descubren nombres; Findomain es un complemento. DNS público comprueba resolución y conserva relaciones nombre–IP. Shodan y Censys buscan IPs candidatas por dominio, certificados y organización, con contraste RDAP. Esta fase termina en el inventario; las pruebas de servicios comienzan en Evaluación completa.")
    if st.button("Iniciar reconocimiento",type="primary",disabled=not st.session_state.scope or "connection" not in st.session_state):
        try:
            with st.status("Reconociendo…",expanded=True) as progress:
                scope=st.session_state.scope
                result=recognize(scope["domain"],progress,scope["ips"])
                st.session_state.scan=rebuild(result)
                save_checkpoint(result)
                progress.update(label="Inventario construido",state="complete")
            st.rerun()
        except Exception as exc: st.error(str(exc))
    if data:
        st.success("Inventario construido")
    nav(data is not None)
elif page==6:
    if not data: st.info("Ejecuta reconocimiento o carga un proyecto para ver el inventario.")
    else:
        rows=[{"Activo":h,"Tipo":"IP declarada" if h in data.get("explicit_ips",[]) else "FQDN",
               "Relaciones DNS":", ".join(data.get("dns_ips",{}).get(h,[])),
               "Estado":"Elegible" if h in data["hosts"] else data.get("dns_records",{}).get(h,{}).get("status","Pendiente de comprobación DNS pública"),
               "Fuente":", ".join(data.get("sources",{}).get(h,["Alcance declarado"]))}
              for h in sorted(set(data["subdomains"])|set(data.get("explicit_ips",[])))]
        st.dataframe(rows,use_container_width=True)
        st.info("La próxima fase evalúa el inventario completo. Un candidato sin IP pública no puede recibir un sondeo TCP; permanece visible y se revalida al reconocer de nuevo.")
        for h,row in data.get("dns_records",{}).items():
            if h not in data["hosts"]:
                with st.expander("Diagnóstico DNS · "+h): st.json(row)
        st.download_button("Guardar inventario JSON",json.dumps(data,ensure_ascii=False,indent=2),"inventario_externo.json","application/json")
    nav(bool(data and data["hosts"]))
elif page==7:
    st.write("Nmap evalúa servicios de todo el inventario mediante las IPs públicas conservadas. NSE revisa TLS y condiciones web; Nikto y pruebas HTTP específicas complementan la revisión. Los fallos quedan visibles y no cuentan como cumplimiento.")
    zap_enabled=True
    st.caption("ZAP se ejecuta como parte obligatoria de la evaluación web: Client Spider y análisis pasivo desde Kali.")
    with st.expander("Tiempos de ZAP por sitio"):
        st.caption("15 minutos iniciales. Se amplía mientras avance; finaliza al 100 % y con cero respuestas pasivas pendientes. Sin avance durante 15 minutos o al alcanzar el límite, registra estado parcial.")
        st.number_input("Máximo de recorrido por sitio (minutos)",15,240,60,key="zap_max_minutes")
        st.number_input("Máximo de espera pasiva por sitio (minutos)",1,120,30,key="zap_passive_max_minutes")
    if data: st.info("Se evaluará el inventario completo. Los resultados compatibles ya terminados se reutilizan automáticamente.")
    if st.button("Evaluar inventario completo",type="primary",disabled=not data or not data["hosts"] or "connection" not in st.session_state):
        try:
            with st.status("Evaluando inventario completo…",expanded=True) as progress:
                result=evaluate_inventory(data,progress)
                collect_posture(result,run_tool,progress)
                from web_stage import collect as collect_web
                collect_web(result,run_tool,progress,zap_enabled)
                config=st.session_state.get("api_config",{})
                enrich(result,config,progress)
                st.session_state.scan=rebuild(result)
                save_checkpoint(result)
                from report_workflow import ensure
                ensure(result,generate_narrative,progress)
                save_checkpoint(result)
                snapshot(result)
                progress.update(label="Ejecución terminada; revisa cobertura y fallos",state="complete")
            st.rerun()
        except Exception as exc:
            st.error(str(exc)+". Puedes cargar el checkpoint de resultados para reanudar.")
    nav(data is not None)
elif page==8:
    if not data: st.info("Carga un proyecto o ejecuta reconocimiento.")
    else:
        d=dashboard_data(data)
        tabs=st.tabs(["Inventario","Servicios","Cobertura","Hallazgos","Herramientas","Web","Protección y TLS","Evidencias"])
        with tabs[0]:
            cols=st.columns(4)
            for c,label,key in zip(cols,["Nombres candidatos","DNS A","IPs DNS","IPs declaradas sin FQDN"],["candidate_names","resolved_names","dns_ips","ip_without_fqdn"]): c.metric(label,d[key])
            extra=st.columns(2)
            extra[0].metric('IPs candidatas de fuentes públicas',d['candidate_ips'])
            extra[1].metric('Candidatas sin FQDN observado',d['candidate_ips_without_fqdn'])
            st.dataframe(d["assets"],use_container_width=True)
            st.caption("IPs DNS son relaciones observadas; su titularidad puede corresponder a un CDN o proveedor.")
        with tabs[1]:
            st.metric("Puertos abiertos observados",d["open_port_observations"])
            if d["ports_by_type"]: st.bar_chart(pd.DataFrame(d["ports_by_type"]),x="Puerto",y="Observaciones")
            st.dataframe(d["services"],use_container_width=True)
        with tabs[2]:
            total=len(data["hosts"]); done=len(set(data["scanned"]))
            st.metric("Sondeo Nmap",f"{done} / {total}")
            st.progress(done/total if total else 0)
            st.dataframe([{"Activo":h,"Nmap":"Completado" if h in data["scanned"] else "No completado"} for h in data["hosts"]],use_container_width=True)
            st.caption("Completar Nmap no significa completar todas las pruebas web ni confirmar ausencia de vulnerabilidades.")
        with tabs[3]:
            obs=data.get("observations",[])
            st.metric("Observaciones únicas",len(obs))
            st.dataframe([{k:o.get(k) for k in ("id","asset","title","status","risk")} for o in obs],use_container_width=True)
        with tabs[4]:
            st.dataframe([{k:r.get(k,"") for k in ("tool","status","stderr")} for r in data["results"]],use_container_width=True)
        with tabs[5]:
            st.write("Acceso web observado y contraste con navegador")
            st.dataframe([{k:r.get(k) for k in ("url","http_status","application_access","browser")} for r in data.get("web_access",[])],use_container_width=True)
            for r in data.get("zap_reports",[]):
                with st.expander("ZAP · "+r["url"]+" · "+r.get("status","ERROR")): st.json(r)
            st.dataframe([{k:o[k] for k in ("asset","fact","status")} for o in data.get("observations",[]) if o["title"]=="Aplicación web identificada"],use_container_width=True)
        with tabs[6]:
            st.write("Señales de protección web")
            st.dataframe([{k:o[k] for k in ("asset","fact","status")} for o in data.get("observations",[]) if o["title"]=="Protección web detectada"],use_container_width=True)
            st.write("Protocolos TLS observados")
            from nmap_checks import tls_summary
            st.dataframe(tls_summary(data),use_container_width=True)
            st.write("Ejecuciones TLS")
            st.dataframe([{k:r.get(k,"") for k in ("tool","status","stderr")} for r in data["results"] if r["tool"].startswith("Nmap web/TLS")],use_container_width=True)
            st.caption("Nmap conserva protocolos/cifrados observados. No observado no equivale a deshabilitado; TLS 1.3 se contrasta con negociación directa.")
        with tabs[7]:
            from consulting_report import visual_for
            cols=st.columns(2)
            cols[0].metric("Imágenes registradas",len(data.get("visual_evidence",[])))
            cols[1].metric("Observaciones con imagen",sum(bool(visual_for(data,o)) for o in data.get("observations",[])))
            st.dataframe([{"Observación":o["id"],"Activo":o["asset"],"Imágenes":len(visual_for(data,o))} for o in data.get("observations",[])],use_container_width=True)
            for error in data.get("visual_errors",[]):st.warning(error)
    nav(data is not None)
elif page==9:
    if not data: st.info("Completa el reconocimiento y las pruebas para calcular postura.")
    else:
        p=calculate(data)

        cols=st.columns(4)
        cols[0].metric("Cumplimiento acreditado sobre 100",p["score"] if p["score"] is not None else "—")
        cols[1].metric("Cobertura de controles %",p["coverage"])
        cols[2].metric("Límite superior por pendientes",p["interval"][1])
        cols[3].metric("Controles incumplidos",len(p["critical_alerts"]))
        st.write("**Clasificación:** "+p["category"])
        from posture import explanation
        st.write(explanation(data,p))
        tabs=st.tabs(["Métricas y motivos","Inteligencia pública","Metodología","Histórico","Validación documentada"])
        with tabs[0]:
            st.dataframe([{"Dimensión":d["name"],"Peso %":d["weight"]*100,"Nota":str(round(d["score"],2)) if d["score"] is not None else "No evaluado",
                "Evaluados":str(d["done"])+"/"+str(d["planned"]),"Cumplidos":d["passed"],"Parciales":d["partial"],"Incumplidos":d["failed"],"Sin evidencia":d["unknown"],"Cobertura %":round(d["coverage"],2)} for d in p["dimensions"]],use_container_width=True)
            web_checks=[c for c in p["checks"] if c["dimension"]=="W"]
            if web_checks:
                st.write("Estado de las comprobaciones web")
                st.dataframe([{"Activo":c["asset"],"Control":c["title"],"Estado":c["status"],"Motivo":c["evidence"] if c["status"]!="Evaluado" else "Respuesta analizada"} for c in web_checks],use_container_width=True)
            for c in p["checks"]:
                with st.expander(c["control"]+" · "+c["asset"]+" · "+c["status"]):
                    st.write(c["reason"]);st.write("Penalización: "+str(c["penalty"]));st.code(c["evidence"] or "Prueba pendiente")
                    from consulting_report import visual_for
                    for o in data.get("observations",[]):
                        if o["asset"]==c["asset"] and (o["title"]==c["title"] or c["control"]=="E-01" and o["title"]=="Servicios TCP accesibles"):
                            for v in visual_for(data,o):st.image(base64.b64decode(v["image_b64"]),caption=v["source"])
        with tabs[1]:
            st.info("Las señales públicas no confirman infección ni pertenencia del activo. Sin registros no significa sin compromiso. No se incluyen en el puntaje inicial.")
            if st.button("Consultar / actualizar fuentes sobre todo el inventario"):
                with st.status("Consultando fuentes públicas…",expanded=True) as progress:
                    enrich(data,st.session_state.get("api_config",{}),progress);save_checkpoint(data)
                    progress.update(label="Consulta finalizada; revisar errores y cuotas",state="complete")
                st.rerun()
            intel=data.get("public_intelligence",{})
            st.caption("KEV: "+intel.get("kev_version","Sin correlación ejecutada"))
            st.dataframe([{k:r.get(k) for k in ("provider","target","status","queried_at_utc","error")} for r in intel.get("records",[])],use_container_width=True)
            for r in intel.get("records",[]):
                with st.expander(r["provider"]+" · "+r["target"]+" · "+r["status"]):st.json(r.get("data") or {"error":r.get("error")})
            st.json(intel.get("correlations",[]))
        with tabs[2]:
            st.write(p["methodology"])
            st.latex(r"credito_{c,a}=1-p_{c,a};\quad credito_{pendiente}=0")
            st.latex(r"S_d=100\frac{\sum_c a_c\overline{credito_c}}{\sum_c a_c},\quad P=\frac{\sum_d w_dS_d}{\sum_d w_d}")
            st.write("Penalizaciones: cumple=0; menor=0.25; importante=0.60; crítica=1. Los indicios ZAP aportan penalización según riesgo y confianza. Las pruebas pendientes aportan cero crédito sin afirmar incumplimiento confirmado. No aplica requiere justificación.")
            st.write("85–100 Favorable; 65–<85 Moderada; 40–<65 Deficiente; 0–<40 Crítica. El rango inferior/superior considera todos los pendientes como incumplidos/cumplidos. El puntaje conservador mantiene pendientes dentro del denominador con cero crédito; solo excluye No aplica justificado. La categoría describe cumplimiento acreditado, no seguridad absoluta.")
            st.write("Cobertura: controles-activo completados / controles-activo aplicables previstos. Inventario completo significa todos los activos elegibles conocidos; el sondeo sigue limitado a 100 puertos TCP por host y las fuentes no garantizan descubrir toda Internet.")
        with tabs[3]:
            if st.button("Guardar fotografía de postura"):snapshot(data);st.success("Evaluación histórica guardada")
            entries=history(data["domain"])
            st.dataframe([{"Fecha":e["date"],"Versión":e["posture"]["version"],"Nota":e["posture"]["score"],"Cobertura":e["posture"]["coverage"],"Activos":len(e["hosts"])} for e in entries],use_container_width=True)
            if len(entries)>1:
                before=entries[-2];after=entries[-1]
                a={(c["control"],c["asset"]):c for c in before["posture"]["checks"]}
                b={(c["control"],c["asset"]):c for c in after["posture"]["checks"]}
                st.write("Cambios entre las dos últimas fotografías")
                st.dataframe([{"Control":k[0],"Activo":k[1],"Antes":str(a.get(k,{}).get("penalty")),"Después":str(b.get(k,{}).get("penalty")),"Estado anterior":a.get(k,{}).get("status"),"Estado actual":b.get(k,{}).get("status")} for k in sorted(set(a)|set(b)) if a.get(k)!=b.get(k)],use_container_width=True)
                st.caption("Comparar cambios de inventario, cobertura y metodología antes de interpretar una variación como mejora.")
        with tabs[4]:
            st.write("Documenta una comprobación externa realizada. La aplicación no confirma por sí sola las conclusiones introducidas por el analista.")
            options={c["control"]+" · "+c["asset"]:c for c in p["checks"]}
            if options:
                selected=st.selectbox("Control y activo",list(options))
                state=st.selectbox("Resultado",["No evaluado","Cumple","Menor","Importante","Crítica","No aplica"])
                evidence=st.text_area("Evidencia pública, referencia de herramienta/captura, justificación y CVE si procede")
                if st.button("Guardar validación",disabled=not evidence.strip()):
                    old=options[selected];values={"Cumple":0,"Menor":.25,"Importante":.6,"Crítica":1}
                    c=check(old["control"],old["asset"],"Evaluado" if state in values else state,values.get(state),evidence,"Validación externa documentada por analista")
                    data["manual_checks"]=[x for x in data.get("manual_checks",[]) if (x["control"],x["asset"])!=(c["control"],c["asset"])]+[c]
                    rebuild(data);save_checkpoint(data);st.rerun()
        st.download_button("Descargar cálculo y controles",json.dumps(p,ensure_ascii=False,indent=2),"postura_calculo_v25.json","application/json")
    nav(data is not None)
elif page==10:
    if not data: st.info("Carga resultados para revisar hallazgos.")
    else:
        for o in data.get("observations",[]):
            with st.expander(o["id"]+" · "+o["asset"]+" · "+o["title"]):
                st.caption("Riesgo: "+o.get("risk","Informativo")+" · "+o.get("risk_reason","")); st.write(o["fact"]); st.write(o["implication"]); st.write("Rutas afectadas: "+", ".join(o.get("affected_urls",[])))
                st.caption("Fuentes: "+", ".join(o["evidence"]))
                from consulting_report import visual_for
                for v in visual_for(data,o): st.image(base64.b64decode(v["image_b64"]),caption=v["source"])
        choices={o["id"]+" · "+o["asset"]:o["id"] for o in data.get("observations",[])}
        image=st.file_uploader("Adjuntar captura PNG/JPG",type=["png","jpg","jpeg"])
        choice=st.selectbox("Observación vinculada",list(choices)) if choices else None
        if st.button("Vincular captura",disabled=image is None or choice is None):
            try:
                raw=image.getvalue()
                if len(raw)>3_000_000: raise ValueError("Máximo 3 MB")
                picture=Image.open(BytesIO(raw)); picture.verify()
                data["visual_evidence"].append({"id":"VIS-"+secrets.token_hex(4).upper(),"observation_id":choices[choice],
                    "source":"Adjuntada por analista; origen no verificable por la app","captured_at_utc":datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "sha256":hashlib.sha256(raw).hexdigest(),"image_b64":base64.b64encode(raw).decode()})
                save_checkpoint(data); st.rerun()
            except Exception as exc: st.error(str(exc))
    nav(data is not None)
else:
    if not data: st.info("Carga resultados para generar el informe.")
    else:
        from manual_review import clear_automatic_review
        clear_automatic_review(data)
        data['organization']=st.session_state.get('organization') or data.get('organization') or data['domain']
        data['project_name']=st.session_state.get('project_name') or data.get('project_name') or 'Evaluación de postura externa'
        from report_workflow import ensure
        from report_context import signature
        config=st.session_state.get('model_config',{})
        data['report_model']={k:config.get(k) for k in ('provider','id')}
        data['report_config_digest']=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()
        data['capture_connection_available']=bool(st.session_state.get('connection'))
        try:
            with st.status('Preparación automática del informe',expanded=False) as progress:
                changed=ensure(data,generate_narrative,progress)
                if changed:save_checkpoint(data)
                progress.update(label='Informe preparado' if data.get('report_preparation',{}).get('complete') else 'Informe preparado con limitaciones documentadas',state='complete')
        except Exception as exc:st.error('No se completó la preparación: '+str(exc))
        ai=data.get('report_ai',{})
        st.caption('Redacción contextual: '+str(ai.get('reviewed',0))+'/'+str(ai.get('total',0))+' · '+ai.get('status','Pendiente'))
        failed={}
        for error in ai.get('errors',[]):
            label=str(error['batch'])+' · '+error['error']
            failed[label]=failed.get(label,0)+1
        if failed:
            st.warning("Qwen no completó todas las redacciones; se conservan las explicaciones del catálogo.")
            with st.expander("Diagnóstico de redacción"):
                st.dataframe([{"Registro":label,"Intentos fallidos":count} for label,count in failed.items()],use_container_width=True)
        for key,title in [("executive","Resumen ejecutivo"),("assessment","Análisis"),("actions","Acciones"),("limitations","Límites")]:
            st.subheader(title)
            st.write(data.get("narrative",{}).get(key,"Pendiente de redacción"))
        from docx_report import missing_visuals
        missing=missing_visuals(data)
        if missing:st.warning('Evidencia visual pendiente en '+str(len(missing))+' condiciones. La aplicación intenta capturarlas al preparar el informe con Kali conectado; puedes adjuntar imágenes en Hallazgos. La descarga se identifica como borrador.')
        try: st.download_button("Descargar borrador DOCX" if missing else "Descargar informe DOCX",report_docx(data),"informe_postura_externa.docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        except Exception as exc: st.error(str(exc))
        st.download_button("Descargar evidencias y checkpoint",json.dumps(data,ensure_ascii=False,indent=2),"evidencias_postura_externa.json","application/json")
        from manual_review import review_prompt
        st.subheader("Revisión manual con Claude")
        st.caption("Sube el DOCX y el JSON a Claude junto con este prompt. La revisión documental no ejecuta un retest; requiere nuevas pruebas y evidencias.")
        prompt=review_prompt(data)
        st.download_button("Descargar prompt para Claude",prompt,"PROMPT_REVISION_CLAUDE.md","text/markdown")
        with st.expander("Ver prompt de revisión"):
            st.code(prompt,language="markdown")
    nav(False)
