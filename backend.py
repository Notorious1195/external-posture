"""Asistente local de evaluación de superficie externa: Streamlit -> Kali SSH -> modelo de IA."""
import base64
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import secrets
import shlex
import socket
import time
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlsplit

import paramiko
import pandas as pd
import requests
import streamlit as st
from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.utils import simpleSplit
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from xml.sax.saxutils import escape
from intelligence import build_observations, grounded_sections
from consulting_report import report_md as consultant_md, report_pdf as consultant_pdf
from docx_report import report_docx, missing_visuals
from evidence_capture import capture_result, output_excerpt
from assets import public_ips, dns_ip_map, dashboard_data


DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
MAX_OUT = 4_000_000

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class ToolTimeout(TimeoutError):
    def __init__(self, seconds, output, stderr):
        super().__init__(f"La herramienta superó {seconds} segundos; salida parcial conservada.")
        self.output, self.stderr = output, stderr


def domain_ok(value):
    value = value.strip().lower().rstrip(".")
    if not DOMAIN.fullmatch(value):
        raise ValueError("Ingresa un dominio completo válido, por ejemplo empresa.com.")
    return value


def in_scope(host, domain):
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def fp_of(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def probe_host(host, port):
    with socket.create_connection((host, port), timeout=8) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=8)
            return fp_of(transport.get_remote_server_key())
        finally:
            transport.close()


def ssh_command(host, port, username, password, expected_fp, argv, timeout=90, stdin_data=None, progress_callback=None):
    """Never execute chat text as a command. All argv are constructed by this app."""
    if not expected_fp:
        raise RuntimeError("Primero confirma la identidad SSH de Kali.")
    sock = socket.create_connection((host, port), timeout=8)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=8)
        if fp_of(transport.get_remote_server_key()) != expected_fp:
            raise RuntimeError("Cambió la identidad SSH de Kali; se canceló antes de enviar la contraseña.")
        transport.auth_password(username, password)
        if not transport.is_authenticated():
            raise RuntimeError("Kali rechazó las credenciales SSH.")
        channel = transport.open_session(timeout=8)
        channel.exec_command(" ".join(shlex.quote(x) for x in argv))
        if stdin_data is not None:
            channel.sendall(stdin_data.encode())
        channel.shutdown_write()
        stdout, stderr = bytearray(), bytearray()
        progress_buffer = ""
        deadline = time.monotonic() + timeout
        while True:
            if channel.recv_ready():
                stdout.extend(channel.recv(65536))
            if channel.recv_stderr_ready():
                chunk=channel.recv_stderr(65536)
                stderr.extend(chunk)
                if progress_callback:
                    progress_buffer+=chunk.decode('utf-8','replace')
                    while '\n' in progress_buffer:
                        line,progress_buffer=progress_buffer.split('\n',1)
                        if line.startswith('ZAP_PROGRESS '):
                            try:progress_callback(json.loads(line[len('ZAP_PROGRESS '):]))
                            except (ValueError,TypeError):pass
            if len(stdout) + len(stderr) > MAX_OUT:
                channel.close()
                raise RuntimeError("La salida excedió el límite de 4 MB; resultado no considerado completo.")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                channel.close()
                raise ToolTimeout(timeout, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace"))
            time.sleep(.08)
        return channel.recv_exit_status(), stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
    finally:
        transport.close()


def run_tool(name, argv, timeout=90, input_text=None, progress_callback=None):
    s = st.session_state
    try:
        connection = s.connection
        rc, out, err = ssh_command(connection["host"], connection["port"], connection["user"],
                                   connection["password"], connection["fingerprint"], argv, timeout, input_text,
                                   **({"progress_callback":progress_callback} if progress_callback else {}))
        limited = name.startswith(("FFUF", "Nikto")) and any(x in out+err for x in ("Maximum running time", "Scan terminated", "maxtime"))
        if rc != 0 and not err.strip():
            err = f"Código {rc}. Salida estándar: {out[:700] or 'vacía'}. Consultar preflight y versión de la herramienta."
        return {"tool": name, "status": "PARCIAL" if limited else ("OK" if rc == 0 else "ERROR"), "exit": rc,
                "output": ANSI.sub("", out), "stderr": ANSI.sub("", err)[:1200], "command": " ".join(shlex.quote(x) for x in argv)}
    except ToolTimeout as exc:
        return {"tool": name, "status": "PARCIAL", "exit": None, "output": ANSI.sub("", exc.output),
                "stderr": str(exc) + " " + ANSI.sub("", exc.stderr)[:900],
                "command": " ".join(shlex.quote(x) for x in argv)}
    except Exception as exc:
        return {"tool": name, "status": "ERROR", "exit": None, "output": "",
                "stderr": str(exc)[:1200], "command": " ".join(shlex.quote(x) for x in argv)}


def lines_in_scope(text, domain):
    found = set()
    for line in text.splitlines():
        candidate = line.strip().split()[0].lower().rstrip(".") if line.strip() else ""
        if DOMAIN.fullmatch(candidate) and in_scope(candidate, domain):
            found.add(candidate)
    return found


def urls_in_scope(text, domain, explicit_ips=None):
    found = set()
    for line in text.splitlines():
        url = line.strip().split()[0] if line.strip() else ""
        try:
            u = urlsplit(url)
            if u.scheme in ("http", "https") and u.hostname and (in_scope(u.hostname, domain) or u.hostname in (explicit_ips or [])):
                found.add(url)
        except ValueError:
            pass
    return found


def resolved_names(text, candidates):
    """DNSx -a -resp: only first-field names with an IPv4 answer qualify."""
    found = set()
    for line in ANSI.sub("", text).splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].lower().rstrip(".")
        if name not in candidates:
            continue
        for token in parts[1:]:
            try:
                if ipaddress.ip_address(token.strip("[]," )).version == 4 and ipaddress.ip_address(token.strip("[]," )).is_global:
                    found.add(name)
                    break
            except ValueError:
                continue
    return found


def qwen(messages, schema=None, meta=None):
    # Qwen is the only model used by this application; a JSON schema constrains LM Studio's output grammar.
    from llm_client import complete
    return complete(st.session_state.model_config,messages,schema=schema,meta=meta)
qwen.accepts_schema=qwen.accepts_meta=True



def generate_narrative(data, progress):
    from manual_review import clear_automatic_review
    clear_automatic_review(data)
    from public_sources import correlate_cached
    from access_policy import normalize
    normalize(data)
    correlate_cached(data)
    previous=list(data.get("observations",[]))
    data["observations"], data["coverage"] = build_observations(data)
    from evidence_capture import relink_visuals
    relink_visuals(previous,data["observations"],data.get("visual_evidence",[]))
    data["organization"]=st.session_state.get("organization") or data.get("organization") or data["domain"]
    data["project_name"]=st.session_state.get("project_name") or data.get("project_name") or "Evaluación de postura externa"
    needs_visual=bool(missing_visuals(data))
    if (data.pop("capture_tool_outputs", False) or needs_visual) and "connection" in st.session_state:
        connection = st.session_state.connection
        data["visual_errors"]=[]
        def remote(argv, timeout=25, stdin_data=None):
            return ssh_command(connection["host"], connection["port"], connection["user"],
                               connection["password"], connection["fingerprint"], argv, timeout, stdin_data)
        for observation in data["observations"]:
            for ref in observation["evidence"]:
                # HTTPx tendrá su captura en la ficha web del mismo activo.
                if ref == "HTTPx Toolkit" and observation["title"] == "Servicios TCP accesibles":
                    continue
                result = next((item for item in data["results"] if item["tool"] == ref and
                               output_excerpt(observation, item).strip()), None)
                if not result and ref.startswith('Inteligencia pública · '):
                    cve=ref.split(' · ',1)[1]
                    correlation=next((c for c in data.get('public_intelligence',{}).get('correlations',[]) if c['cve']==cve),None)
                    if correlation:result={'tool':ref,'status':'OK','output':json.dumps(correlation,ensure_ascii=False,indent=2),'command':'Consulta pública registrada; aplicabilidad pendiente'}
                if not result:
                    continue
                if any(v.get("observation_id")==observation["id"] and ref in v.get("source","") for v in data.get("visual_evidence",[])): continue
                try:
                    progress.write("Capturando salida registrada: " + ref + " · " + observation["id"])
                    data.setdefault("visual_evidence", []).append(capture_result(observation, result, remote))
                except Exception as exc:
                    data.setdefault("visual_errors", []).append(ref + " · " + observation["id"] + ": " + str(exc)[:180])
    if not data.get("hosts"):
        raise RuntimeError("Sin nombres resueltos ni IPs declaradas para interpretar.")
    cov = data["coverage"]
    data.pop("analysis_warnings", None)
    drafts = data["narrative"] = {}
    drafts["assessment"], drafts["actions"] = grounded_sections(data, data["observations"], cov)
    digest = {"candidatos": cov["candidates"], "con_dns_a": cov["dns_a"],
              "sondeados_nmap": cov["scanned"], "puertos_observados": cov["open_ports"],
              "urls_historicas_devueltas": cov["historical_urls"],
              "herramientas_incompletas": cov["incomplete_tools"],
              "aplicaciones_web_observadas": sum(o["title"] == "Aplicación web identificada" for o in data["observations"]),
              "waf_solo_indicio": any(o["title"] == "Protección web detectada" for o in data["observations"]),
              "ips_declaradas": len(data.get("explicit_ips", []))}
    from report_ai import compose
    config=st.session_state.get("model_config",{})
    model_signature=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()
    if data.get('report_model_signature')!=model_signature:data.pop('report_ai',None)
    from llm_client import writer as make_writer
    writer=None
    data['model_diagnostic']={'status':'NO CONFIGURADO'}
    if config:
        try:
            progress.write('Comprobando una petición breve de redacción antes de enviar los hallazgos…')
            # Worker threads cannot read st.session_state; the writer captures the configuration and sizes concurrency.
            writer=make_writer(config,int(config.get('parallel',3)))
            writer([{'role':'system','content':'Responde exactamente con la palabra OK.'},{'role':'user','content':'Comprobación de conexión'}])
            data['model_diagnostic']={'status':'OK'}
        except Exception as exc:
            data['model_diagnostic']={'status':'ERROR','error':str(exc)[:500]}
            writer=None
    compose(data,writer,progress)
    if data['model_diagnostic']['status']=='ERROR':
        data['report_ai']['status']='PARCIAL'
        data['report_ai']['errors'].append({'batch':'conexión','attempt':1,'error':data['model_diagnostic']['error']})
    data['report_model_signature']=model_signature
    data['report_model']={k:config.get(k) for k in ('provider','id')}

    data["analysis"]=data["narrative"]["executive"]
    data["narrative_complete"]=True


def read_nmap(xml):
    rows = []
    if not xml.strip():
        return rows
    root = ET.fromstring(xml)
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr", "") if address is not None else ""
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.get("state") != "open":
                continue
            rows.append({"ip": ip, "port": port.get("portid", ""),
                         "protocol": port.get("protocol", ""),
                         "service": service.get("name", "") if service is not None else "",
                         "product": service.get("product", "") if service is not None else ""})
    return rows


def capture_web(url, domain, progress, explicit_ips=None):
    """Screenshot of an in-scope page from Kali Chromium; never synthesize evidence."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or not (in_scope(parsed.hostname, domain) or parsed.hostname in (explicit_ips or [])):
        raise ValueError("La URL de captura está fuera del dominio autorizado.")
    connection = st.session_state.connection
    def remote(argv, timeout=25):
        return ssh_command(connection["host"], connection["port"], connection["user"],
                           connection["password"], connection["fingerprint"], argv, timeout)
    browser = None
    for candidate in ("chromium", "chromium-browser"):
        rc, _, _ = remote(["which", candidate], 12)
        if rc == 0:
            browser = candidate
            break
    if not browser:
        raise RuntimeError("Chromium no está instalado en Kali. Instálalo para capturas automáticas o adjunta capturas manuales.")
    token = secrets.token_hex(10)
    target = "/tmp/postura-externa-" + token + ".png"
    profile = "/tmp/postura-perfil-" + token
    try:
        progress.write("Capturando página real: " + url)
        rc, _, err = remote([browser, "--headless", "--disable-gpu", "--disable-dev-shm-usage",
                             "--hide-scrollbars", "--window-size=1280,800", "--virtual-time-budget=6000",
                             "--user-data-dir=" + profile, "--screenshot=" + target, url], 65)
        if rc != 0:
            raise RuntimeError("Chromium terminó con código " + str(rc) + ": " + err[:300])
        rc, encoded, err = remote(["base64", "-w", "0", "--", target], 20)
        if rc != 0 or not encoded:
            raise RuntimeError("No se pudo recuperar la captura desde Kali: " + err[:200])
        raw = base64.b64decode(encoded, validate=True)
        if not raw.startswith(b"\x89PNG\r\n\x1a\n") or len(raw) > 1_000_000:
            raise RuntimeError("La captura no es un PNG válido o supera 1 MB.")
        return {"id": "VIS-" + token[:8].upper(), "url": url,
                "captured_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "source": "Chromium en Kali", "sha256": hashlib.sha256(raw).hexdigest(),
                "image_b64": base64.b64encode(raw).decode("ascii")}
    finally:
        try:
            remote(["rm", "-rf", "--", target, profile], 12)
        except Exception:
            pass



from pathlib import Path

def save_checkpoint(data):
    data["organization"]=st.session_state.get("organization") or data.get("organization") or data["domain"]
    data["project_name"]=st.session_state.get("project_name") or data.get("project_name") or "Evaluación de postura externa"
    folder = Path("resultados")
    folder.mkdir(exist_ok=True)
    target = folder / (data["domain"] + "-checkpoint.json")
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(target)

def recognize(domain, progress, explicit_ips=None):
    explicit_ips = explicit_ips or []
    if "connection" not in st.session_state:
        raise RuntimeError("Completa la prueba de conexión SSH antes de evaluar.")
    preflight = run_tool("SSH previo", ["nmap", "--version"], 20)
    if preflight["status"] != "OK":
        raise RuntimeError("Se perdió la conexión con Kali: " + preflight["stderr"])
    results = []
    sources = {domain: ["dominio inicial"]}
    candidates = {domain}

    def add(name, args, timeout=75, input_text=None):
        progress.write(f"Ejecutando {name}…")
        result = run_tool(name, args, timeout, input_text)
        results.append(result)
        progress.write(f"{name}: {result['status']}" + (f" — {result['stderr'][:100]}" if result['status'] != 'OK' else ""))
        return result

    for name, args in [("Subfinder", ["subfinder", "-d", domain, "-silent", "-max-time", "3"])]:
        item = add(name, args, 210)
        for host in lines_in_scope(item["output"], domain):
            candidates.add(host)
            sources.setdefault(host, []).append(name)
    findomain_path = run_tool("Findomain disponible", ["which", "findomain"], 15)
    if findomain_path["status"] == "OK":
        found = add("Findomain", ["findomain", "-t", domain, "-q"], 180)
        for host in lines_in_scope(found["output"], domain):
            candidates.add(host); sources.setdefault(host, []).append("Findomain")
    else:
        progress.write("Findomain opcional no instalado; otras fuentes siguen activas.")

    go_path = add("Ruta Go", ["go", "env", "GOPATH"], 15)
    wayback_path = posixpath.join(go_path["output"].strip(), "bin", "waybackurls") if go_path["status"] == "OK" else "waybackurls"
    wayback = add("waybackurls", [wayback_path], 100, domain + "\n")
    gau = add("GetAllURLs", ["getallurls", "-subs", domain], 100)
    historical = urls_in_scope(wayback["output"], domain) | urls_in_scope(gau["output"], domain)
    for url in historical:
        host = urlsplit(url).hostname
        candidates.add(host)
        if "Archivo histórico" not in sources.setdefault(host, []):
            sources[host].append("Archivo histórico")

    # Optional CT candidates enabled in APIs page. Failure does not erase inventory.
    if st.session_state.get("api_config", {}).get("ct_enabled", True):
        from public_sources import passive_names
        try:
            for host in passive_names(domain):
                candidates.add(host); sources.setdefault(host, []).append("Certificate Transparency · crt.sh")
        except Exception as exc:
            results.append({"tool":"CT crt.sh","status":"ERROR","output":"","stderr":str(exc),"command":"Public CT query"})

    # Public dataset supplies candidates only; fresh DNS validates active targets.
    config=st.session_state.get("api_config",{})
    dnsdumpster=None
    if config.get("dnsdumpster_enabled",True):
        key=config.get("keys",{}).get("DNSDumpster",os.environ.get("DNSDUMPSTER_API_KEY",""))
        if key:
            from public_sources import lookup,sanitize
            progress.write("Consultando DNSDumpster…")
            try:
                dnsdumpster=sanitize(lookup("DNSDumpster",domain,key),[key])
                if not isinstance(dnsdumpster,dict) or dnsdumpster.get("error"):raise ValueError("Respuesta DNSDumpster inválida o error del proveedor")
                for section in ("a","cname","mx","ns"):
                    for row in dnsdumpster.get(section,[]):
                        for host in lines_in_scope(str(row.get("host","")),domain):
                            candidates.add(host)
                            if "DNSDumpster" not in sources.setdefault(host,[]):sources[host].append("DNSDumpster")
                results.append({"tool":"DNSDumpster","status":"OK","output":json.dumps(dnsdumpster,ensure_ascii=False),"stderr":"Datos limitados por el plan del proveedor; no acredita descubrimiento exhaustivo","command":"Consulta API pública DNSDumpster"})
            except Exception as exc:
                results.append({"tool":"DNSDumpster","status":"ERROR","output":"","stderr":str(exc),"command":"Consulta API pública DNSDumpster"})
        else:progress.write("DNSDumpster: introduce la clave en APIs para habilitar reconocimiento")

    # Resolve every passive candidate; only resolved names qualify for active probes.
    dns = add("DNSx", ["dnsx", "-a", "-resp", "-silent"], 100, "\n".join(sorted(candidates)) + "\n")
    resolved = resolved_names(dns["output"], candidates)
    dns_addresses = dns_ip_map(dns["output"], candidates)
    from reliable_dns import resolve
    dns_records, dns_results = resolve(sorted(candidates), run_tool, progress)
    results.extend(dns_results)
    for host, row in dns_records.items():
        if row.get("addresses"):
            dns_addresses[host] = row["addresses"]; resolved.add(host)
    for host in candidates:
        if host not in resolved:
            dns_records.setdefault(host, {"addresses":[], "status":"Sin resolución pública", "attempts":[]})
    dns_hosts = ([domain] if domain in resolved else []) + sorted(resolved - {domain})
    hosts = (explicit_ips + [host for host in dns_hosts if host not in explicit_ips])
    data = {"domain": domain, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "results": results, "sources": sources, "subdomains": sorted(candidates),
            "resolved": sorted(resolved), "dns_ips": dns_addresses, "dns_records": dns_records, "explicit_ips": explicit_ips,
            "hosts": hosts, "scanned": [], "ports": [], "historical_count": len(historical),
            "visual_evidence": [], "visual_errors": [], "phase": "inventory", "analysis": "Reconocimiento terminado."}
    data["dnsdumpster"]=dnsdumpster
    data['organization']=st.session_state.get('organization') or domain
    data['project_name']=st.session_state.get('project_name') or 'Evaluación de postura externa'
    from ip_discovery import discover
    discover(data,config,progress,remote=run_tool)
    # Search providers may reveal additional names under the authorized domain.
    extra_names=set()
    for candidate in data.get('ip_candidates',[]):
        for name in candidate.get('names',[]):
            extra_names.update(lines_in_scope(str(name).removeprefix('*.'),domain))
    extra_names-=set(data['subdomains'])
    if extra_names:
        extra_records,extra_results=resolve(sorted(extra_names),run_tool,progress)
        data['results'].extend(extra_results);data['dns_records'].update(extra_records)
        data['subdomains']=sorted(set(data['subdomains'])|extra_names)
        for name,row in extra_records.items():
            data['sources'][name]=['Descubrimiento IP; nombres relacionados']
            if row.get('addresses'):
                data['dns_ips'][name]=row['addresses'];data['resolved']=sorted(set(data['resolved'])|{name})
        data['hosts']=sorted(set(data['resolved'])|set(data['explicit_ips']))
    for candidate in data.get('ip_candidates',[]):
        candidate['inventory_names']=sorted(name for name,values in data['dns_ips'].items() if candidate['ip'] in values)
        candidate['no_fqdn_observed']=not(candidate['names'] or candidate['inventory_names'])
    data["observations"], data["coverage"] = build_observations(data)
    return data

def evaluate_inventory(inventory, progress):
    data = json.loads(json.dumps(inventory))
    domain = domain_ok(data["domain"])
    data["explicit_ips"] = public_ips("\n".join(data.get("explicit_ips", [])),limit=65536)
    hosts = data["hosts"] = sorted(set(data.get("resolved", [])) | set(data.get("explicit_ips", [])))
    resolved, dns_addresses = set(data["resolved"]), data.get("dns_ips", {})
    explicit_ips, sources, candidates = data.get("explicit_ips", []), data.get("sources", {}), set(data["subdomains"])
    if not hosts:
        raise ValueError("El inventario no tiene objetivos elegibles")
    if any(not (in_scope(h, domain) or h in explicit_ips) for h in hosts):
        raise ValueError("El inventario contiene un objetivo fuera del dominio o alcance IP declarado")
    results = data["results"]
    def add(name, args, timeout=75, input_text=None):
        command = " ".join(shlex.quote(x) for x in args)
        cached = next((r for r in results if r["tool"] == name and r.get("command") == command and r.get("input_sha256") == hashlib.sha256((input_text or "").encode()).hexdigest() and r["status"] == "OK"), None)
        if cached:
            progress.write(name + ": resultado conservado")
            return cached
        progress.write("Ejecutando " + name + "…")
        result = run_tool(name, args, timeout, input_text)
        result["input_sha256"] = hashlib.sha256((input_text or "").encode()).hexdigest()
        results[:] = [r for r in results if not (r["tool"] == name and r.get("command") == command)]
        results.append(result)
        data["results"] = results
        save_checkpoint(data)
        progress.write(name + ": " + result["status"])
        return result
    host_input = "\n".join(hosts) + "\n"
    http = add("HTTPx Toolkit", ["httpx-toolkit", "-sc", "-title", "-td", "-silent", "-no-color", "-t", "5"], 180, host_input) if host_input.strip() else {"output": ""}
    web_urls = sorted(urls_in_scope(http["output"], domain, explicit_ips))
    from access_policy import REMOTE_PROBE
    data['web_preflight']=[]
    def restricted(url):
        latest=run_tool("Acceso antes de pruebas · "+url,['python3','-c',REMOTE_PROBE,url],20)
        results.append(latest)
        try:row=json.loads(latest.get('output',''))
        except ValueError:row={'url':url,'status':'ERROR','blocked':True,'reason':'Sondeo sin respuesta válida'}
        data['web_preflight'].append(row)
        denied=row.get('blocked') or latest.get('status')!='OK'
        if denied:progress.write('Aplicación no evaluable; se omiten pruebas web dependientes · '+url)
        return denied
    blocked={url for url in web_urls if restricted(url)}
    for url in web_urls:
        try:data.setdefault("visual_evidence",[]).append(capture_web(url,domain,progress,explicit_ips))
        except Exception as exc:data.setdefault("visual_errors",[]).append(url+": "+str(exc)[:240])
    # HTTPx puede producir líneas con anotaciones; tomamos únicamente URLs del primer campo.
    if not web_urls:
        progress.write("HTTPx no confirmó aplicaciones web; se omiten pruebas web dependientes.")

    from reliable_dns import targets, resolve
    # Refresh only missing transport addresses, retaining public inventory answers.
    missing=[h for h in hosts if not targets(data,h)]
    if missing:
        recovered, dns_results=resolve(missing,run_tool,progress);results.extend(dns_results)
        data.setdefault("dns_records",{}).update(recovered)
        for h,row in recovered.items():
            if row.get("addresses"):data.setdefault("dns_ips",{})[h]=row["addresses"]
    ports, scanned = [], []
    for host in hosts:
        addresses=targets(data,host)
        if not addresses:
            results.append({"tool":"Nmap · "+host,"status":"ERROR","exit":None,"output":"",
                "stderr":"Sin IP pública conservada; no se usa DNS local para adivinar el destino","command":"No ejecutado"})
            continue
        completed=True
        for address in addresses:
            label="Nmap · "+host+" · "+address
            scan=add(label,["nmap","-sT","-Pn","-n","-T2","--top-ports","100","-sV","--version-light","-oX","-","--",address],900)
            try:
                root=ET.fromstring(scan["output"])
                if not root.findall("host") or scan["status"]!="OK": completed=False
                for row in read_nmap(scan["output"]):
                    row["host"]=host;ports.append(row)
            except ET.ParseError:
                completed=False;scan["status"]="PARCIAL";scan["stderr"]+=" XML incompleto"
        if completed:scanned.append(host)
        data["ports"],data["scanned"]=ports,scanned;save_checkpoint(data)
    # Naabu removed: Nmap provides the port inventory.

    # Fuentes históricas: no visitan automáticamente todas las URLs recuperadas.
    go_path = add("Ruta Go", ["go", "env", "GOPATH"], 15)
    wayback_path = posixpath.join(go_path["output"].strip(), "bin", "waybackurls") if go_path["status"] == "OK" else "waybackurls"
    wayback = add("waybackurls", [wayback_path], 100, domain + "\n")
    gau = add("GetAllURLs", ["getallurls", "-subs", domain], 100)
    historical = urls_in_scope(wayback["output"], domain) | urls_in_scope(gau["output"], domain)

    for url in web_urls:
        if url in blocked:continue
        add("Katana · " + url, ["katana", "-u", url, "-d", "1", "-ct", "15s", "-rl", "2", "-fs", "fqdn", "-silent"], 55)
        add("Wafw00f · " + url, ["wafw00f", url], 50)
    # FFUF: lista pequeña incorporada a la aplicación, sin fuerza bruta extensa.
    # FFUF requiere archivo de wordlist; no lo lanzamos con una ruta incontrolada.
    # SecLists de Kali proporciona una lista; limitamos el volumen vía -maxtime y -rate.
    for url in web_urls:
        if url in blocked or restricted(url):continue
        add("FFUF · " + url, ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
                     "-u", url.rstrip("/") + "/FUZZ", "-rate", "2", "-maxtime", "45",
                     "-ac", "-json", "-s", "-noninteractive"], 65)
    # Mixed web checks: NSE + Nikto; Nuclei is a bounded optional complement.
    from nmap_checks import tls_checks, nse_observations
    from urllib.parse import urlsplit
    data["nse_indications"]=[]
    tls_rows=[]
    for url in web_urls:
        parsed=urlsplit(url);host=parsed.hostname;port=parsed.port or (443 if parsed.scheme=="https" else 80)
        addresses=targets(data,host)
        for address in addresses:
            scripts="http-security-headers,http-cookie-flags"
            if parsed.scheme=="https":scripts+=",ssl-cert,ssl-enum-ciphers"
            r=add("Nmap web/TLS · "+url+" · "+address,["nmap","-sT","-Pn","-n","-sV","--version-light",
                "-p",str(port),"--script",scripts,"--script-args","tls.servername="+host+",http.host="+host,
                "--script-timeout","180s","-oX","-","--",address],600)
            data["nse_indications"].extend(nse_observations(r,url))
            if parsed.scheme=="https":tls_rows.append(tls_checks(r,url))
        for address in addresses:
            if url in blocked or restricted(url):break
            nikto=add("Nikto · "+url+" · "+address,["nikto","-h",address,"-port",str(port),"-vhost",host]+
                (["-ssl"] if parsed.scheme=="https" else [])+["-Tuning","123b","-maxtime","300s",
                "-timeout","8","-nointeractive"],360)
    data["nmap_tls_checks"]=tls_rows
    visuals, visual_errors = list(data.get("visual_evidence", [])), list(data.get("visual_errors", []))
    for url in web_urls:
        if any(v.get("url") == url for v in visuals): continue
        try:
            visuals.append(capture_web(url, domain, progress, explicit_ips))
        except Exception as exc:
            visual_errors.append(url + ": " + str(exc)[:240])
            progress.write("Captura no disponible: " + visual_errors[-1])
            if "no está instalado" in str(exc):
                break
    return {**data, "domain": domain, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "results": results, "sources": sources, "subdomains": sorted(candidates),
            "resolved": sorted(resolved), "dns_ips": dns_addresses, "explicit_ips": explicit_ips,
            "hosts": hosts, "scanned": scanned, "ports": ports, "historical_count": len(historical),
            "active_cap": None, "nmap_top_ports": 100,
            "visual_evidence": visuals, "visual_errors": visual_errors,
            "capture_tool_outputs": True, "phase": "evaluated",
            "analysis": ""}
