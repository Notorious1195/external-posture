"""Evidence-backed external exposure brief and consultancy report rendering."""
import json
import re
from collections import Counter
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def build_observations(data):
    """Only deterministic, traceable facts; no inferred CVEs or vulnerabilities."""
    obs = []
    results = data.get("results", [])

    seen = set()
    def add(title, status, asset, fact, implication, next_step, refs):
        key = (title.casefold(), asset.lower().rstrip('/'), fact.casefold())
        if key in seen:
            return
        seen.add(key)
        obs.append({"id": f"EXT-{len(obs)+1:03d}", "title": title, "status": status,
                    "asset": asset, "fact": fact, "implication": implication,
                    "recommendation": next_step, "evidence": refs})

    for row in data.get("web_access",[]):
        if row.get("http_status") in (401,403):
            add("Acceso web restringido", "Confirmado", row["url"],
                "El sondeo HTTP recibió "+str(row["http_status"])+". La configuración observada corresponde a esa respuesta; no acredita las páginas normales.",
                "La restricción limita la cobertura de la aplicación; no confirma WAF ni vulnerabilidad.",
                "Contrastar captura del navegador y respuestas accesibles desde Kali.", ["Controles postura · "+row["url"]])
    grouped={}
    from finding_model import origin
    rule_controls={'10020':'W-01','10021':'W-02'}
    for report in data.get("zap_reports",[]):
        from access_policy import unavailable
        if report.get("application_evaluable") is False or unavailable(data,report.get("url","")):continue
        for alert in report.get("alerts",[]):
            if str(alert.get('confidence','')).lower() in ('false positive','0'):continue
            url=alert.get('url',report['url'])
            if origin(url)!=origin(report['url']):continue
            key=(str(alert.get('alertRef') or alert.get('pluginId','')),origin(url))
            g=grouped.setdefault(key,{'alert':alert,'urls':[],'refs':[],'observed':[]})
            if url not in g['urls']:g['urls'].append(url)
            # ZAP's description is generic for the rule; 'evidence' is what this response actually contained.
            value=str(alert.get('evidence') or '').strip()[:200]
            if value and value not in g['observed'] and len(g['observed'])<12:g['observed'].append(value)
            ref='ZAP · '+report['url']
            if ref not in g['refs']:g['refs'].append(ref)
    for (rule,application),g in grouped.items():
        alert=g['alert']
        base_rule=str(alert.get('pluginId',''))
        add("ZAP: "+alert.get("name","Observación pasiva"),"Indicio",application,
            alert.get("description","")[:2500],"Señal pasiva que requiere corroboración. No se ha confirmado explotación.",
            alert.get("solution","")[:1500],g['refs'])
        obs[-1].update(condition=rule_controls.get(base_rule,'ZAP-'+rule),affected_urls=g['urls'],zap_alert_name=str(alert.get('name',''))[:200],zap_description=alert.get('description','')[:2500],zap_observed=g['observed'],zap_risk=str(alert.get('risk','')),zap_rule=base_rule,zap_alert_ref=rule,zap_params=sorted({str(a.get('param','')) for report in data.get('zap_reports',[]) for a in report.get('alerts',[]) if str(a.get('alertRef') or a.get('pluginId',''))==rule and origin(a.get('url',''))==application}))
    ports = list(data.get("ports", []))  # Positive XML observations survive a partial scan; no clean conclusion.
    by_endpoint = {}
    for p in ports:
        ip=p.get("ip") or p["host"]
        record=by_endpoint.setdefault(ip,{"values":set(),"hosts":set()})
        record["values"].add(f"{p['port']}/{p['protocol']}");record["hosts"].add(p["host"])
    for address, row in sorted(by_endpoint.items()):
        refs=[r["tool"] for r in results if r["tool"].startswith("Nmap · ") and
              any(r["tool"].startswith("Nmap · "+h+" · "+address) for h in row["hosts"])]
        add("Servicios TCP accesibles", "Confirmado", address,
            "Nmap observó abiertos: "+", ".join(sorted(row["values"]))+". FQDN relacionados: "+", ".join(sorted(row["hosts"]))+".",
            "Servicios observados en la misma IP se consolidan; los FQDN pueden corresponder a sitios virtuales distintos. No demuestra titularidad ni vulnerabilidad.",
            "Revisar necesidad de exposición y comprobar correcciones desde Internet.",refs)

    for item in results:
        name, out = item["tool"], ANSI.sub("", item.get("output", ""))
        if name == "HTTPx Toolkit" and item["status"] == "OK":
            for line in out.splitlines():
                m = re.match(r"(https?://\S+)\s+\[(\d{3})\]", line)
                if m:
                    technologies = [x for x in ("WordPress", "Nginx", "PHP", "Google Cloud CDN") if x.lower() in line.lower()]
                    add("Aplicación web identificada", "Confirmado", m.group(1),
                        f"HTTPx obtuvo HTTP {m.group(2)}" + (" e identificó " + ", ".join(technologies) if technologies else "") + ".",
                        "La identificación tecnológica orienta la revisión; no confirma versiones vulnerables.",
                        "Comprobar versiones y configuraciones mediante evidencia pública y pruebas externas autorizadas.", [name])
        if name.startswith("Wafw00f ·") and item["status"] == "OK":
            match = re.search(r"behind\s+([^\n]+?)\s+WAF", out, re.I)
            if match:
                add("Protección web detectada", "Indicio", name.split(" · ", 1)[1],
                    "Wafw00f detectó una señal compatible con " + match.group(1).strip(" .!")[:90] + ".",
                    "La detección de WAF no demuestra que todas las rutas estén protegidas.",
                    "La detección pública no permite verificar la cobertura completa de WAF.", [name])
        if name.startswith("Nuclei · ") and out.strip():
            for line in out.splitlines():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = obj.get("info", {})
                title = str(info.get("name") or obj.get("template-id") or "Coincidencia de plantilla")[:110]
                asset = str(obj.get("matched-at") or obj.get("host") or data["domain"])[:180]
                if not obj.get("template-id"):
                    continue
                add(title, "Indicio", asset,
                    "Nuclei reportó coincidencia de plantilla " + str(obj.get("template-id", "sin ID"))[:100] + ".",
                    "Una coincidencia automática requiere validación antes de declararse vulnerabilidad.",
                    "Validar la condición y el impacto; solo entonces asignar severidad o CVE.", [name])
    # Nikto is an independent source of indications, not automatic confirmation.
    from posture import checks_for
    validated=checks_for(data)
    corroborations={}
    verified_routes={(c["asset"], {"V-02":"/.git/HEAD","V-03":"/.env","V-04":"/phpinfo.php"}.get(c["control"]))
                     for c in validated if c.get("status")=="Evaluado" and c.get("penalty",0)>0}
    for r in results:
        if r.get("tool","").startswith("Nikto · "):
            url=r["tool"].split(" · ")[1]
            for line in r.get("output","").splitlines():
                if not line.startswith("+ ") or not re.search(r"^\+ /|CVE-|OSVDB-|vulnerab",line,re.I):continue
                confirmed=next((c for c in validated if c.get("status")=="Evaluado" and c.get("penalty",0)>0 and c["asset"]==url and
                    ((c["control"]=="V-02" and "/.git/" in line) or (c["control"]=="V-03" and "/.env" in line) or (c["control"]=="V-04" and "phpinfo" in line.lower()))),None)
                if confirmed:
                    corroborations.setdefault((confirmed["control"],confirmed["asset"]),[]).append(r["tool"]);continue
                add("Señal web: "+line[2:100],"Indicio",url,line[2:600],
                    "Nikto observó una condición que debe corroborarse; no se asigna severidad por el nombre del producto.",
                    "Repetir una comprobación específica y conservar la respuesta que demuestra la condición.",[r["tool"]])
                if 'x-frame-options' in line.lower() and any(x in line.lower() for x in ('not present','not defined','missing')):obs[-1]['condition']='W-01'
                elif 'x-content-type-options' in line.lower() and any(x in line.lower() for x in ('not set','not present','missing')):obs[-1]['condition']='W-02' 
    for item in data.get("nse_indications",[]):
        add(item["template"],"Indicio",item["asset"],item["fact"],"Resultado NSE pendiente de corroboración.",
            "Comprobar la condición mediante una prueba específica.",[item["source"]])
    from posture import checks_for
    for c in checks_for(data):
        if c.get("status") == "Evaluado" and c.get("penalty", 0) > 0:
            # Service exposure is explained in posture against the existing port observation.
            if c["control"] in ("E-01","V-01"): continue
            ref = next((r["tool"] for r in results if r["tool"] == c.get("source")), None) or next((r["tool"] for r in results if r["tool"].startswith("Controles postura ·") and
                        c["evidence"] in r.get("output", "")), None)
            if not ref:
                ref = next((r["tool"] for r in results if r["tool"].startswith("Controles postura ·") and
                    (c["asset"] in r.get("tool", "") or c["control"].startswith("D-"))), c.get("source", "Prueba documentada"))
            add(c["title"], "Confirmado", c["asset"], c["evidence"], "La prueba documenta una deficiencia conforme al criterio: "+c["reason"],
                "Corregir la condición documentada y repetir el mismo control desde Internet.", list(dict.fromkeys([ref]+corroborations.get((c["control"],c["asset"]),[]))))
            obs[-1].update(control=c["control"],condition=c["control"],control_penalty=c['penalty'])

    for report in data.get('zap_reports',[]):
        for form in report.get('password_forms',[]):
            from urllib.parse import urlsplit
            if urlsplit(form.get('action','')).scheme!='http':continue
            page=form.get('page',report['url'])
            add('Formulario de contraseña con destino HTTP','Confirmado',page,
                json.dumps({'page':page,'action':form['action'],'method':form['method'],'password_fields':form['password_fields'],'observation':'Configuración del formulario observada en HTML; no se enviaron credenciales ni se verificó una sesión autenticada'},ensure_ascii=False),
                'El formulario declara un destino HTTP para un campo de contraseña. La configuración permite un envío sin cifrado; no se afirma haber observado credenciales reales en tránsito.',
                'Utilizar una acción HTTPS verificable para el formulario y comprobar redirecciones, recursos y cookies sin enviar credenciales reales.',
                ['ZAP · '+report['url']])
            obs[-1].update(condition='T-03',control='T-03',control_penalty=1,password_form=True)
    for cve in data.get('public_intelligence',{}).get('correlations',[]):
        for asset in cve.get('assets',[]):
            add('CVE reportada por una fuente pública: '+cve['cve'],'Indicio',asset,
                'La fuente '+', '.join(cve.get('sources',[]))+' asocia '+cve['cve']+' al activo. Fecha de consulta: '+str(cve.get('queried_at_utc',''))+'. Aplicabilidad no confirmada.',
                'La coincidencia pública orienta la validación; requiere comprobar componente, configuración y parche. KEV/EPSS contextualizan prioridad y no confirman aplicabilidad.',
                'Verificar versión, condición afectada y actualización aplicable; repetir una comprobación específica sin asumir explotabilidad.',
                ['Inteligencia pública · '+cve['cve']])
            obs[-1].update(condition='CVE-'+cve['cve'])
    errors = [f"{x['tool']}: {x['status']}" for x in results if x["status"] != "OK"]
    coverage = {"candidates": len(data.get("subdomains", [])), "dns_a": len(data.get("resolved", [])),
                "scanned": len(data.get("scanned", [])), "selected": len(data.get("hosts", [])),
                "open_ports": len(ports), "historical_urls": data.get("historical_count", 0),
                "incomplete_tools": errors}
    from finding_model import consolidate
    from redaction import text
    for o in obs:
        for k in ("fact","implication","recommendation"):o[k]=text(o[k])
    return consolidate(obs), coverage


def evidence_digest(data, observations, coverage):
    """Bounded input for a small local model; all refs resolve to tool names in JSON."""
    return {"domain": data["domain"], "date_utc": data["date"], "coverage": coverage,
            "observations": [{k: x[k] for k in ("id", "title", "status", "asset", "fact", "implication", "evidence")}
                             for x in observations[:8]]}


def grounded_sections(data, observations, coverage):
    """Keep asset-to-fact links and recommended actions deterministic."""
    confirmed, indications = [], []
    for item in observations:
        line = f"{item['asset']}: {item['fact']} ({item['id']})."
        (confirmed if item['status'] == 'Confirmado' else indications).append(line)
    assessment = (f"Se registraron {len(confirmed)} observaciones confirmadas de servicios o aplicaciones y "
                  f"{len(indications)} indicios automáticos que requieren validación. "
                  "Los hechos, activos y capturas aparecen una sola vez en las fichas siguientes. "
                  f"Quedaron {len(set(data.get('resolved', [])) - set(data.get('scanned', [])))} nombres con DNS A sin sondeo Nmap. "
                  "Un puerto abierto, una respuesta 404 o una identificación de tecnología no confirman vulnerabilidades.")

    def ids(predicate):
        return ", ".join(o["id"] for o in observations if predicate(o))

    dev = [o for o in observations if o["title"] == "Aplicación web identificada" and re.search(r"(?:dev|desa|test|stage|qa)", o["asset"], re.I)]
    web = [o for o in observations if o["title"] == "Aplicación web identificada" and "WordPress" in o["fact"]]
    waf = [o for o in observations if o["title"] == "Protección web detectada"]
    ports = [o for o in observations if o["title"] == "Servicios TCP accesibles"]
    actions = []
    if dev:
        o = dev[0]
        actions.append(f"1. Confirmar con el propietario si {o['asset']} debe estar publicado. Si no existe necesidad de acceso externo, restringirlo o retirarlo; verificar después desde una red externa que el acceso cambió según lo aprobado ({o['id']}).")
    if ports:
        actions.append(f"{len(actions)+1}. Revisar con los responsables la necesidad de los servicios observados en {', '.join(o['asset'] for o in ports)}. Documentar los puertos permitidos y verificar las reglas de exposición tras cualquier cambio ({ids(lambda o: o in ports)}).")
    if web:
        o = web[0]
        actions.append(f"{len(actions)+1}. Verificar mediante evidencia pública las versiones y actualizaciones de WordPress, Nginx y PHP del activo {o['asset']}; aplicar correcciones que procedan y comprobar versiones y acceso a rutas administrativas mediante revisión autorizada ({o['id']}).")
    if waf:
        actions.append(f"{len(actions)+1}. Verificar externamente los indicios de protección con solicitudes benignas autorizadas; no concluir sobre reglas internas ({ids(lambda o: o in waf)}).")
    if not actions:
        actions.append("1. Confirmar el inventario y completar las pruebas pendientes antes de definir remediaciones específicas.")
    if coverage['incomplete_tools']:
        actions.append(f"{len(actions)+1}. Diagnosticar y repetir las herramientas incompletas ({'; '.join(coverage['incomplete_tools'])}) para ampliar la cobertura y reducir la incertidumbre de la calificación.")
    return assessment, "\n".join(actions)


def narrative(data):
    defaults = {"executive": "Análisis de Qwen no disponible. La evidencia técnica requiere revisión humana.",
                "assessment": "No se produjo interpretación automática.",
                "actions": "Revisar los registros y validar los indicios.",
                "limitations": "La cobertura activa y las herramientas incompletas impiden una puntuación defendible."}
    return defaults | (data.get("narrative") or {})


def report_md(data):
    obs, cov, n = data["observations"], data["coverage"], narrative(data)
    lines = ["# Informe de inteligencia de superficie externa", "",
             f"**Dominio:** {data['domain']}  ", f"**Fecha UTC:** {data['date']}  ",
             "**Clasificación de distribución:** por definir por el propietario del informe.  ",
             "**Estado:** preliminar, sujeto a validación humana.", "",
             "## Resumen ejecutivo", "", n["executive"], "", "## Alcance y metodología", "",
             "Reconocimiento pasivo de nombres y comprobación DNS A; sondeo del inventario elegible completo con cien puertos TCP frecuentes por objetivo. "
             "Análisis automatizado desde Kali vía SSH y redacción asistida por el modelo elegido. Las pruebas se ejecutaron desde un único punto de observación.", "",
             f"Se descubrieron {cov['candidates']} nombres candidatos, {cov['dns_a']} respondieron con registro A y Nmap registró {cov['scanned']} hosts. "
             f"Se observaron {cov['open_ports']} puertos abiertos. Las fuentes históricas consultadas devolvieron {cov['historical_urls']} URLs; cero no acredita ausencia.", "",
             "## Análisis de exposición", "", n["assessment"], "", "## Hallazgos y observaciones", ""]
    if not obs:
        lines += ["No hay vulnerabilidades confirmadas ni observaciones técnicas suficientes para clasificarlas. Esto no equivale a ausencia de riesgo.", ""]
    for x in obs:
        lines += [f"### {x['id']} · {x['title']}", "", f"**Estado:** {x['status']}  ",
                  f"**Activo:** {x['asset']}  ", f"**Hecho observado:** {x['fact']}  ",
                  f"**Interpretación:** {x['implication']}  ", f"**Acción:** {x['recommendation']}  ",
                  f"**Evidencia:** {', '.join(x['evidence'])} en evidencias_postura_externa.json.", ""]
    lines += ["## Acciones prioritarias", "", n["actions"], "", "## Confianza, cobertura y límites", "", n["limitations"], ""]
    if cov["incomplete_tools"]:
        lines += ["Herramientas incompletas: " + "; ".join(cov["incomplete_tools"]) + ".", ""]
    lines += ["Un nombre candidato puede no resolver; un puerto abierto no prueba una vulnerabilidad. "
              "Una coincidencia de plantilla es un indicio hasta validación. No se evaluaron todos los activos ni se asigna calificación global o CVE sin prueba suficiente.", "",
              "## Trazabilidad", "", "Los identificadores de herramienta citados en cada observación corresponden a entradas del JSON de evidencias. "
              "La salida técnica completa permanece allí; el informe presenta el análisis y las decisiones derivadas."]
    return "\n".join(lines)


def report_pdf(data):
    obs, cov, n = data["observations"], data["coverage"], narrative(data)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#15375b"), alignment=TA_CENTER, spaceAfter=16))
    styles.add(ParagraphStyle(name="ReportBody", parent=styles["BodyText"], leading=15, spaceAfter=8))
    styles.add(ParagraphStyle(name="ReportSmall", parent=styles["BodyText"], fontSize=8, leading=11, spaceAfter=5))
    styles["Heading2"].textColor = colors.HexColor("#15375b")
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=(595, 842), leftMargin=46, rightMargin=46, topMargin=46, bottomMargin=46)
    story = [Paragraph("Informe de inteligencia de superficie externa", styles["ReportTitle"]),
             Paragraph(escape(f"Dominio: {data['domain']}  |  Fecha UTC: {data['date']}"), styles["ReportBody"]),
             Paragraph("Preliminar, sujeto a validación humana. Clasificación de distribución: por definir.", styles["ReportSmall"])]

    def formatted_line(value):
        parts = re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", value)
        formatted = []
        for part in parts:
            if part.startswith("**") and part.endswith("**"):
                formatted.append("<b>" + escape(part[2:-2]) + "</b>")
            elif part.startswith("`") and part.endswith("`"):
                formatted.append("<font color='#15375b'>" + escape(part[1:-1]) + "</font>")
            else:
                formatted.append(escape(part))
        return "".join(formatted)

    def section(title, value):
        story.append(Paragraph(title, styles["Heading2"]))
        for part in value.strip().split("\n"):
            if part.strip():
                line = part.strip()
                prefix = "&bull; " if line.startswith("- ") else ""
                if prefix:
                    line = line[2:]
                story.append(Paragraph(prefix + formatted_line(line), styles["ReportBody"]))

    section("Resumen ejecutivo", n["executive"])
    story.append(Paragraph("Alcance y metodología", styles["Heading2"]))
    story.append(Paragraph("Reconocimiento pasivo, comprobación DNS A y sondeo activo de inventario elegible completo, con cien puertos TCP frecuentes por objetivo. Punto de observación único: Kali vía SSH. Redacción asistida por el modelo elegido.", styles["ReportBody"]))
    rows = [["Indicador", "Resultado"], ["Nombres candidatos", str(cov["candidates"])],
            ["Con respuesta DNS A", str(cov["dns_a"])], ["Hosts sondeados por Nmap", str(cov["scanned"])],
            ["Puertos abiertos observados", str(cov["open_ports"])], ["URLs históricas devueltas", str(cov["historical_urls"])]]
    table = Table(rows, colWidths=[330, 165], hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8eef4")),
                               ("GRID", (0,0), (-1,-1), .35, colors.lightgrey),
                               ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 7)]))
    story.extend([table, Spacer(1, 10)])
    section("Análisis de exposición", n["assessment"])
    story.append(Paragraph("Hallazgos y observaciones", styles["Heading2"]))
    if not obs:
        story.append(Paragraph("No hay observaciones técnicas suficientes para confirmar vulnerabilidades. Esto no equivale a ausencia de riesgo.", styles["ReportBody"]))
    for x in obs:
        block = [Paragraph(escape(x["id"] + "  " + x["title"]), styles["Heading3"]),
                 Paragraph(escape(f"Estado: {x['status']}  |  Activo: {x['asset']}"), styles["ReportSmall"]),
                 Paragraph(escape("Hecho: " + x["fact"]), styles["ReportBody"]),
                 Paragraph(escape("Interpretación: " + x["implication"]), styles["ReportBody"]),
                 Paragraph(escape("Acción: " + x["recommendation"]), styles["ReportBody"]),
                 Paragraph(escape("Evidencia: " + ", ".join(x["evidence"]) + " en el JSON adjunto."), styles["ReportSmall"])]
        story.append(KeepTogether(block[:3]))
        story.extend(block[3:])
    section("Acciones prioritarias", n["actions"])
    section("Confianza y límites", n["limitations"])
    if cov["incomplete_tools"]:
        story.append(Paragraph(escape("Herramientas incompletas: " + "; ".join(cov["incomplete_tools"])), styles["ReportSmall"]))
    story.append(Paragraph("No se asigna puntuación global ni CVE sin cobertura y validación suficientes. Cero URLs históricas devueltas no demuestra ausencia de exposición. Los detalles técnicos completos están en evidencias_postura_externa.json.", styles["ReportSmall"]))
    doc.build(story)
    return buf.getvalue()
