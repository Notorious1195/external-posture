"""Capture a faithful, labeled view of stored tool output using Kali Chromium."""
import base64
import hashlib
import html
import json
import re
import secrets
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


def normalized_host(value):
    from urllib.parse import urlsplit
    return (urlsplit(value).hostname or value).lower().rstrip(".")


def output_excerpt(observation, result):
    name = result["tool"]
    output = result.get("output", "")
    if name.startswith('Controles postura ·'):
        try:
            rows=json.loads(output)
            selected=[r for r in rows if r.get('control')==observation.get('control') and normalized_host(r.get('asset',''))==normalized_host(observation['asset'])]
            return json.dumps(selected,ensure_ascii=False,indent=2) if selected else ''
        except ValueError:return ''
    if name.startswith('ZAP ·'):
        try:
            obj=json.loads(output);condition=observation.get('condition','')
            rule=condition.removeprefix('ZAP-') if condition.startswith('ZAP-') else {'W-01':'10020','W-02':'10021'}.get(condition)
            selected=[a for a in obj.get('alerts',[]) if str(a.get('alertRef') or a.get('pluginId'))==rule or str(a.get('pluginId'))==rule]
            return json.dumps(selected[:5],ensure_ascii=False,indent=2) if selected else ''
        except ValueError:return ''
    if name.startswith("Nmap · "):
        try:
            root = ET.fromstring(output)
            lines = []
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    lines.append(ET.tostring(port, encoding="unicode"))
            return "\n".join(lines[:20]) or output[:5000]
        except ET.ParseError:
            return output[:5000]
    if name == "HTTPx Toolkit":
        return "\n".join(line for line in output.splitlines()
                         if line.startswith(observation["asset"] + " ") or
                         (observation["title"] == "Servicios TCP accesibles" and
                          re.match(r"https?://" + re.escape(normalized_host(observation["asset"])) +
                                   r"(?:[:/\s]|$)", line)))[:5000]
    if name.startswith("Nuclei · "):
        return "\n".join(line for line in output.splitlines()
                         if observation["asset"] in line)[:5000]
    if name == "Naabu" or name.startswith("Naabu · "):
        return "\n".join(line for line in output.splitlines()
                         if normalized_host(observation["asset"]) in line)[:5000]
    return output[:5000]


def capture_result(observation, result, remote):
    from redaction import text
    excerpt = text(output_excerpt(observation, result))
    if not excerpt.strip():
        raise ValueError("La salida de la herramienta no contiene el resultado vinculado.")
    token = secrets.token_hex(8)
    html_path = "/tmp/postura-salida-" + token + ".html"
    png_path = "/tmp/postura-salida-" + token + ".png"
    profile = "/tmp/postura-perfil-" + token
    page = ("<!doctype html><meta charset='utf-8'><style>body{background:#101820;color:#e6edf3;"
            "font:16px monospace;padding:22px}h1{font-size:19px}pre{white-space:pre-wrap;overflow-wrap:anywhere;"
            "line-height:1.4}</style><h1>Salida técnica registrada</h1>"
            "<p>Herramienta: " + html.escape(result["tool"]) + "</p><p>Activo: " +
            html.escape(observation["asset"]) + "</p><p>Comando: " +
            html.escape("Comando remoto de comprobación; consultar bitácora" if "python" in result.get("command", "") else result.get("command", "")) + "</p><pre>" + html.escape(excerpt) + "</pre>")
    writer = "import sys;open(sys.argv[1],'w',encoding='utf-8').write(sys.stdin.read())"
    try:
        rc, _, err = remote(["python3", "-c", writer, html_path], 20, page)
        if rc:
            raise RuntimeError("No se pudo preparar la vista: " + err[:200])
        rc, _, err = remote(["chromium", "--headless", "--disable-gpu", "--disable-dev-shm-usage",
                             "--window-size=1280,900", "--user-data-dir=" + profile,
                             "--screenshot=" + png_path, "file://" + html_path], 65)
        if rc:
            raise RuntimeError("Chromium no capturó la salida: " + err[:200])
        rc, encoded, err = remote(["base64", "-w", "0", png_path], 20)
        raw = base64.b64decode(encoded, validate=True)
        if rc or not raw.startswith(b"\x89PNG\r\n\x1a\n") or len(raw) > 3_000_000:
            raise RuntimeError("Imagen de salida inválida o demasiado grande.")
        return {"id": "VIS-" + token[:8].upper(), "observation_id": observation["id"], "render_version":20,
                "captured_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "source": "Chromium en Kali: vista de salida registrada de " + result["tool"] +
                          " (no es captura de una terminal en vivo)",
                "sha256": hashlib.sha256(raw).hexdigest(), "image_b64": base64.b64encode(raw).decode("ascii")}
    finally:
        try:
            remote(["rm", "-rf", "--", html_path, png_path, profile], 12)
        except Exception:
            pass


def matching_result(observation, results):
    for ref in observation["evidence"]:
        for result in results:
            if result["tool"] == ref and result.get("output") and output_excerpt(observation, result).strip():
                return result
    return None

def relink_visuals(previous,current,visuals):
    """Sequential EXT ids can shift. Never attach an old screenshot by id alone."""
    def identity(o):return (o.get('title'),o.get('asset'),o.get('fact'))
    old={o['id']:identity(o) for o in previous}
    new={identity(o):o['id'] for o in current}
    aliases={old_id:o['id'] for o in current for old_id in o.get('legacy_ids',[])}
    # HAL ids hash condition and origin, so a surviving HAL id is the same finding even if its title was retranslated.
    stable={o['id'] for o in current if str(o.get('id','')).startswith('HAL-')}
    for v in visuals:
        ref=v.get('observation_id')
        if ref in stable and v.get('render_version')==20:continue
        if v.get('render_version')!=20 and any(x in v.get('source','') for x in ('vista de salida registrada de Controles postura','vista de salida registrada de ZAP')):
            v['archived_observation_id']=ref;v['observation_id']='ARCHIVED-'+str(ref);continue
        if ref in old:
            replacement=new.get(old[ref])
            # Migration of old per-URL ZAP evidence only when family and origin agree.
            if not replacement:
                from finding_model import origin
                title,asset,fact=old[ref]
                candidate=next((o for o in current if (o.get('title')==title or title in o.get('source_titles',[])) and origin(o.get('asset',''))==origin(asset) and fact in o.get('fact','')),None)
                replacement=candidate['id'] if candidate else None
            if replacement:v['observation_id']=replacement
            else:
                v['archived_observation_id']=ref
                v['observation_id']='ARCHIVED-'+ref
    return visuals
