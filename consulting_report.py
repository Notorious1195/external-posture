"""Consultancy-style report following the supplied CTI template, adapted to exposure."""
import base64
import re
from io import BytesIO
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether

from intelligence import narrative


def visual_for(data, observation):
    linked = []
    for visual in data.get("visual_evidence", []):
        if visual.get("observation_id") == observation["id"]:
            linked.append(visual)
        elif observation["title"] == "Aplicación web identificada" and visual.get("url") == observation["asset"]:
            linked.append(visual)
    if observation['title']=='Acceso web restringido':
        real=[v for v in data.get('visual_evidence',[]) if v.get('url')==observation['asset'] and v.get('source')=='Chromium en Kali']
        if real:return real
    unique={v.get('sha256',v['id']):v for v in linked}
    return list(unique.values())


def report_md(data):
    n, cov = narrative(data), data["coverage"]
    lines = ["# Informe de ciberinteligencia de superficie externa", "",
             f"**Cliente y dominio evaluado:** {data['domain']}  ",
             f"**Fecha UTC:** {data['date']}  ",
             "**Autor y responsable de aprobación:** por completar por el equipo de seguridad.  ",
             "**Estado:** preliminar, sujeto a validación humana.  ",
             f"**Origen del resumen ejecutivo:** {data.get('summary_source', 'no registrado')}.  ",
             "**TLP de distribución:** pendiente de asignación por el propietario de la información; no expresa severidad.", "",
             "## 1. Resumen ejecutivo", "", n["executive"], "",
             "## 2. Metodología de análisis", "",
             "### Recolección y procesamiento", "",
             "Descubrimiento pasivo de subdominios, comprobación DNS A de candidatos, identificación HTTP y sondeo activo limitado. "
             "Los resultados se correlacionaron por condición y aplicación. El modelo elegido propone un resumen ejecutivo sujeto a control; "
             "las asociaciones activo–evidencia y las acciones se construyen desde los registros estructurados.", "",
             f"Cobertura: {cov['candidates']} candidatos, {cov['dns_a']} nombres con respuesta DNS A, "
             f"{cov['scanned']} hosts sondeados por Nmap, {cov['open_ports']} puertos abiertos observados. "
             f"Las fuentes históricas devolvieron {cov['historical_urls']} URLs; cero no demuestra ausencia.", "",
             "### Consideraciones", "",
             "Un solo punto de observación, el inventario elegible completo y cien puertos TCP frecuentes por host. "
             "Las IP pueden corresponder a CDN o proveedores. Los nombres candidatos no equivalen a activos confirmados.", "",
             "## 3. Análisis de amenazas y exposición", "", n["assessment"], "",
             "No se atribuye actividad a un adversario ni se afirma explotación sin evidencia. Las técnicas de reconocimiento podrían aprovechar información pública, "
             "pero este informe documenta exposición observada, no un incidente.", "",
             "## 4. Detalle de observaciones", ""]
    for x in data["observations"]:
        visuals = visual_for(data, x)
        lines += [f"### {x['id']} · {x['title']}", "", f"**Estado:** {x['status']}  ",
                  f"**Activo:** {x['asset']}  ", f"**Hecho observado:** {x['fact']}  ",
                  f"**Análisis:** {x['implication']}  ", f"**Acción propuesta:** {x['recommendation']}  ",
                  f"**Evidencia técnica:** {', '.join(x['evidence'])} en el JSON.  ",
                  f"**Evidencia visual:** {', '.join(v['id'] for v in visuals) if visuals else 'No aportada para esta observación.'}", ""]
    lines += ["## 5. Indicadores de exposición", "",
              "Los dominios, servicios y tecnologías observados figuran en las fichas anteriores. No se identificaron indicadores de compromiso (IoC) "
              "a partir de estas pruebas; no se investigó un incidente.", "",
              "## 6. Acciones recomendadas", "", n["actions"], "",
              "## 7. Áreas de atención y confianza", "", n["limitations"], ""]
    if cov["incomplete_tools"]:
        lines += ["Herramientas incompletas: " + "; ".join(cov["incomplete_tools"]) + ".", ""]
    if data.get("visual_errors"):
        lines += ["Capturas no obtenidas: " + "; ".join(data["visual_errors"]) + ".", ""]
    if data.get("analysis_warnings"):
        lines += ["Control de redacción: " + "; ".join(data["analysis_warnings"]) + ".", ""]
    lines += ["La postura utiliza reglas explícitas con cobertura separada. No se asignan CVE sin corroboración de aplicabilidad. Una captura de página acredita la vista capturada "
              "en ese momento; no valida por sí sola un puerto, la eficacia del WAF ni una vulnerabilidad.", "",
              "## 8. Distribución e integración", "",
              "El propietario de la información debe asignar TLP y destinatarios antes de difundir el informe. "
              "El equipo de seguridad puede vincular los identificadores EXT a su inventario y plan de remediación; "
              "el JSON conserva las salidas técnicas y los archivos de imagen codificados para trazabilidad.", "",
              "## Anexo A. Evidencia visual", ""]
    if not data.get("visual_evidence"):
        lines += ["No se aportaron capturas. El informe permanece preliminar; adjunta capturas auténticas antes de su emisión.", ""]
    for v in data.get("visual_evidence", []):
        lines += [f"### {v['id']}", "", f"- Origen: {v['source']}",
                  f"- Activo u observación: {v.get('url', v.get('observation_id', 'sin vincular'))}",
                  f"- Capturada o adjuntada (UTC): {v['captured_at_utc']}",
                  f"- SHA-256 de imagen: `{v['sha256']}`", "",
                  "Imagen incluida en el PDF y codificada en el JSON de evidencias.", ""]
    return "\n".join(lines)


def report_pdf(data):
    n, cov = narrative(data), data["coverage"]
    styles = getSampleStyleSheet()
    blue = colors.HexColor("#15375b")
    styles.add(ParagraphStyle(name="CTITitle", parent=styles["Title"], textColor=blue, alignment=TA_CENTER, fontSize=19, leading=24, spaceAfter=18))
    styles.add(ParagraphStyle(name="CTIBody", parent=styles["BodyText"], fontSize=10, leading=14, spaceAfter=7))
    styles.add(ParagraphStyle(name="CTISmall", parent=styles["BodyText"], fontSize=8, leading=11, spaceAfter=5))
    styles["Heading2"].textColor = blue
    styles["Heading3"].textColor = blue
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=(595, 842), leftMargin=48, rightMargin=48, topMargin=45, bottomMargin=46)
    story = [Paragraph("Informe de ciberinteligencia de superficie externa", styles["CTITitle"])]

    def inline(line):
        parts = re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", line)
        return "".join("<b>" + escape(p[2:-2]) + "</b>" if p.startswith("**") and p.endswith("**")
                       else "<font color='#15375b'>" + escape(p[1:-1]) + "</font>" if p.startswith("`") and p.endswith("`")
                       else escape(p) for p in parts)

    def section(title, value):
        story.append(Paragraph(title, styles["Heading2"]))
        for line in value.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("- "):
                line = "&bull; " + inline(line[2:])
            else:
                line = inline(line)
            story.append(Paragraph(line, styles["CTIBody"]))

    metadata = [["Datos del informe", "Valor"], ["Dominio evaluado", data["domain"]],
                ["Fecha UTC", data["date"]], ["Estado", "Preliminar; revisión humana requerida"],
                ["TLP", "Pendiente de asignación; no indica severidad"],
                ["Responsable", "Por completar por el equipo de seguridad"],
                ["Origen del resumen", data.get("summary_source", "No registrado")]]
    table = Table(metadata, colWidths=[170, 320], hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8eef4")),
                               ("GRID", (0,0), (-1,-1), .35, colors.lightgrey),
                               ("VALIGN", (0,0), (-1,-1), "TOP"), ("PADDING", (0,0), (-1,-1), 7)]))
    story.extend([table, Spacer(1, 12)])
    section("1. Resumen ejecutivo", n["executive"])
    section("2. Metodología de análisis", "Recolección pasiva de nombres, comprobación DNS A, identificación HTTP y sondeo activo limitado desde Kali vía SSH. El modelo elegido propone un resumen ejecutivo sujeto a control; las asociaciones activo–evidencia y las acciones provienen de registros estructurados.")
    rows = [["Cobertura", "Resultado"], ["Nombres candidatos", str(cov["candidates"])],
            ["Con DNS A", str(cov["dns_a"])], ["Hosts sondeados por Nmap", str(cov["scanned"])],
            ["Puertos abiertos observados", str(cov["open_ports"])], ["URLs históricas devueltas", str(cov["historical_urls"])]]
    coverage_table = Table(rows, colWidths=[325, 165], hAlign="LEFT")
    coverage_table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8eef4")),
                                       ("GRID", (0,0), (-1,-1), .35, colors.lightgrey),
                                       ("PADDING", (0,0), (-1,-1), 6)]))
    story.extend([coverage_table, Spacer(1, 9)])
    section("Recolección y procesamiento", "Se correlacionaron los resultados por dominio y herramienta. Los candidatos sin DNS A y las herramientas incompletas se separan de los activos observados. Se evaluó el inventario elegible completo; Nmap examina los cien puertos TCP frecuentes por host. Los fallos y pendientes se documentan.")
    section("3. Análisis de amenazas y exposición", n["assessment"])
    story.append(Paragraph("No se atribuye actividad a un adversario ni se afirma explotación sin evidencia. Este ejercicio documenta exposición observada, no un incidente.", styles["CTISmall"]))
    story.append(Paragraph("4. Detalle de observaciones", styles["Heading2"]))
    for x in data["observations"]:
        visuals = visual_for(data, x)
        block = [Paragraph(escape(x["id"] + "  " + x["title"]), styles["Heading3"]),
                 Paragraph(escape(f"Estado: {x['status']}  |  Activo: {x['asset']}"), styles["CTISmall"]),
                 Paragraph(escape("Hecho: " + x["fact"]), styles["CTIBody"])]
        story.append(KeepTogether(block))
        story.extend([Paragraph(escape("Análisis: " + x["implication"]), styles["CTIBody"]),
                      Paragraph(escape("Acción: " + x["recommendation"]), styles["CTIBody"]),
                      Paragraph(escape("Evidencia técnica: " + ", ".join(x["evidence"]) + " en el JSON."), styles["CTISmall"]),
                      Paragraph(escape("Evidencia visual: " + (", ".join(v["id"] for v in visuals) if visuals else "No aportada para esta observación.")), styles["CTISmall"])])
    section("5. Indicadores de exposición", "Los dominios, servicios y tecnologías observados constan en las fichas EXT. No se identificaron IoC mediante esta evaluación de superficie externa y no se investigó un incidente.")
    section("6. Acciones recomendadas", n["actions"])
    section("7. Áreas de atención y confianza", n["limitations"])
    if cov["incomplete_tools"]:
        story.append(Paragraph(escape("Herramientas incompletas: " + "; ".join(cov["incomplete_tools"])), styles["CTISmall"]))
    if data.get("visual_errors"):
        story.append(Paragraph(escape("Capturas no obtenidas: " + "; ".join(data["visual_errors"])), styles["CTISmall"]))
    if data.get("analysis_warnings"):
        story.append(Paragraph(escape("Control de redacción: " + "; ".join(data["analysis_warnings"])), styles["CTISmall"]))
    story.append(Paragraph("No se asigna puntuación global ni CVE sin validación suficiente. Una captura de página no prueba por sí sola un puerto, la eficacia del WAF o una vulnerabilidad.", styles["CTISmall"]))
    section("8. Distribución e integración", "El propietario asignará TLP y destinatarios antes de difundir. Los ID EXT pueden vincularse al inventario y al plan de remediación. El JSON conserva las salidas y las imágenes codificadas.")
    story.append(Paragraph("Anexo A. Evidencia visual", styles["Heading2"]))
    if not data.get("visual_evidence"):
        story.append(Paragraph("No se aportaron capturas auténticas. Adjuntarlas antes de emitir el informe.", styles["CTIBody"]))
    for visual in data.get("visual_evidence", []):
        try:
            raw = base64.b64decode(visual["image_b64"], validate=True)
            picture = PILImage.open(BytesIO(raw))
            if picture.format not in ("PNG", "JPEG") or len(raw) > 3_000_000:
                continue
            picture.verify()
            width, height = PILImage.open(BytesIO(raw)).size
            scale = min(490 / width, 425 / height)
            caption = [Paragraph(escape(f"{visual['id']} · {visual.get('url', visual.get('observation_id', ''))}"), styles["Heading3"]),
                       Paragraph(escape(f"Origen: {visual['source']} | UTC: {visual['captured_at_utc']}"), styles["CTISmall"]),
                       Image(BytesIO(raw), width=width*scale, height=height*scale),
                       Paragraph(escape("SHA-256: " + visual["sha256"]), styles["CTISmall"])]
            story.append(KeepTogether(caption))
            story.append(Spacer(1, 15))
        except (ValueError, OSError, KeyError):
            story.append(Paragraph("Captura omitida por formato inválido: " + escape(visual.get("id", "sin ID")), styles["CTISmall"]))
    doc.build(story)
    return buf.getvalue()
