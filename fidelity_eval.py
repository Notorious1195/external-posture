"""Fidelity evaluation of report drafting: N Qwen runs versus the catalog baseline on the same evidence JSON.

Uso:
  python fidelity_eval.py evidencias.json --runs 5 [--model qwen/qwen3-4b-2507] [--url http://127.0.0.1:1234] [--parallel 3] [--out carpeta]
  python fidelity_eval.py evidencias.json --runs 0      (solo la línea base del catálogo, sin LM Studio)

Salidas en la carpeta indicada (por defecto resultados/fidelidad/<dominio>-<fecha>):
  afirmaciones.csv   una fila por oración del texto que entraría en el informe, con señales automáticas y columnas
                     vacías para la etiqueta humana (respaldada / no respaldada / exagerada)
  ejecuciones.csv    una fila por ejecución: validadas, catálogo, intentos rechazados, tiempo y tokens
  resumen.json       métricas agregadas por condición y estabilidad entre ejecuciones
  procedencia/       report_ai completo de cada ejecución (prompts, hashes, intentos y motivos de rechazo)
The automatic signals are a pre-screen for human labeling, not a verdict: only a reviewer decides fidelity.
"""
import argparse,copy,csv,json,re,statistics,sys
from datetime import datetime,timezone
from itertools import combinations
from pathlib import Path
from types import SimpleNamespace

OVERREACH=re.compile(r'\b(?:tod[ao]s\s+l[ao]s|sin\s+excepci[oó]n|siempre|en\s+tod[ao]|completamente|totalmente|urgente\w*|inmediat\w+|cr[ií]tic[ao]s?|garantiz\w+|cualquier)\b',re.I)
SENTENCE=re.compile(r'(?<=[.!?])\s+(?=[A-ZÁÉÍÓÚÑ¿¡])')
LABELS='respaldada | no respaldada | exagerada'

def rebuild(data):
    """Same preparation as the application before drafting: current observation model and evidence links."""
    from manual_review import clear_automatic_review
    from public_sources import correlate_cached
    from access_policy import normalize
    from intelligence import build_observations,grounded_sections
    from evidence_capture import relink_visuals
    clear_automatic_review(data);normalize(data);correlate_cached(data)
    previous=list(data.get('observations',[]))
    data['observations'],data['coverage']=build_observations(data)
    relink_visuals(previous,data['observations'],data.get('visual_evidence',[]))
    data['narrative']={};data['narrative']['assessment'],data['narrative']['actions']=grounded_sections(data,data['observations'],data['coverage'])
    return data

def drafted_texts(data):
    """Text each finding would carry in the DOCX: the validated note, or the catalog explanation when none passed."""
    from finding_model import human_description
    from report_ai import approved_note
    rows=[]
    for o in data['observations']:
        note=approved_note(data,o);meaning=human_description(o)[1];remediation=human_description(o)[2]
        rows.append((o,'IA' if note else 'catálogo',(note['explanation'] if note else meaning),(note['recommendation'] if note else remediation)))
    return rows

def sentences(text):return [x.strip() for x in SENTENCE.split(text or '') if x.strip()]

def words(text):return set(re.findall(r'\w{4,}',(text or '').lower()))

def jaccard(a,b):return len(a&b)/len(a|b) if a|b else 1.0

def compose_run(data,model):
    from report_ai import compose
    run=copy.deepcopy(data);run.pop('report_ai',None)
    compose(run,model,SimpleNamespace(write=lambda *a:None))
    return run

def claims(run,condition,number):
    from report_ai import ungrounded
    out=[]
    for o,source,explanation,remediation in drafted_texts(run):
        for part,text in (('explicación',explanation),('recomendación',remediation)):
            for i,sentence in enumerate(sentences(text),1):
                missing=ungrounded(sentence,o)
                flag='identificador no observado' if missing else 'posible exageración' if OVERREACH.search(sentence) else ''
                out.append({'condicion':condition,'ejecucion':number,'hallazgo':o['id'],'titulo':o['title'],'estado':o['status'],'riesgo':o['risk'],
                            'origen_texto':source,'parte':part,'n_oracion':i,'oracion':sentence,'senal_automatica':flag,
                            'identificadores_no_observados':', '.join(missing),'etiqueta_humana':'','comentario':''})
    executive=run.get('report_ai',{}).get('executive_interpretation')
    for i,sentence in enumerate(sentences(executive),1):
        out.append({'condicion':condition,'ejecucion':number,'hallazgo':'ejecutivo','titulo':'Interpretación ejecutiva','estado':'','riesgo':'',
                    'origen_texto':'IA','parte':'ejecutivo','n_oracion':i,'oracion':sentence,'senal_automatica':'posible exageración' if OVERREACH.search(sentence) else '',
                    'identificadores_no_observados':'','etiqueta_humana':'','comentario':''})
    return out

def run_row(run,condition,number):
    ai=run.get('report_ai',{});records=[n.get('provenance') for n in ai.get('notes',{}).values() if n.get('provenance')]+list(ai.get('fallbacks',{}).values())
    attempts=[a for r in records for a in r.get('attempts',[])]
    tokens=sum(((a.get('usage') or {}).get('total_tokens') or 0) for a in attempts)
    reasons={}
    for a in attempts:
        if a.get('outcome')!='aceptada':key=re.sub(r':.*','',a.get('reason','sin motivo'))[:90];reasons[key]=reasons.get(key,0)+1
    return {'condicion':condition,'ejecucion':number,'hallazgos':ai.get('total',len(run['observations'])),'validadas_ia':ai.get('reviewed',0) if condition!='catálogo' else 0,
            'texto_catalogo':len(ai.get('fallbacks',{})) if condition!='catálogo' else len(run['observations']),'intentos':len(attempts),
            'intentos_rechazados':sum(a.get('outcome')=='rechazada' for a in attempts),'errores_modelo':sum(a.get('outcome')=='error del modelo' for a in attempts),
            'ejecutivo':(ai.get('executive_provenance') or {}).get('result',''),'segundos':(ai.get('run') or {}).get('elapsed_s',0),'tokens':tokens,
            'paralelo':(ai.get('run') or {}).get('parallel',''),'modelo':(ai.get('run') or {}).get('model') or '','motivos_rechazo':json.dumps(reasons,ensure_ascii=False)}

def summarize(claim_rows,run_rows,qwen_runs,baseline):
    summary={'generado_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),'etiquetas':LABELS,
             'nota':'Las señales automáticas solo priorizan la revisión humana; la fidelidad la decide la etiqueta humana.','condiciones':{}}
    for condition in sorted({r['condicion'] for r in claim_rows}):
        rows=[r for r in claim_rows if r['condicion']==condition]
        runs=[r for r in run_rows if r['condicion']==condition]
        summary['condiciones'][condition]={'ejecuciones':len(runs),'oraciones':len(rows),
            'oraciones_identificador_no_observado':sum(r['senal_automatica']=='identificador no observado' for r in rows),
            'oraciones_posible_exageracion':sum(r['senal_automatica']=='posible exageración' for r in rows),
            'tasa_validacion_ia':round(sum(r['validadas_ia'] for r in runs)/max(1,sum(r['hallazgos'] for r in runs)),4),
            'intentos_rechazados':sum(r['intentos_rechazados'] for r in runs),'errores_modelo':sum(r['errores_modelo'] for r in runs),
            'segundos_media':round(statistics.mean(r['segundos'] for r in runs),2) if runs else 0}
    if len(qwen_runs)>1:
        # Stability: mean pairwise word-overlap of the same finding's explanation across runs.
        per=[]
        for o in qwen_runs[0]['observations']:
            texts=[next(t for x,_,t,_ in drafted_texts(r) if x['id']==o['id']) for r in qwen_runs]
            per.append(statistics.mean(jaccard(words(a),words(b)) for a,b in combinations(texts,2)))
        summary['estabilidad_jaccard_media']=round(statistics.mean(per),4)
    if qwen_runs and baseline:
        base={o['id']:words(t) for o,_,t,_ in drafted_texts(baseline)}
        summary['similitud_con_catalogo_media']=round(statistics.mean(jaccard(words(t),base[o['id']]) for r in qwen_runs for o,s,t,_ in drafted_texts(r) if s=='IA'),4) if any(s=='IA' for r in qwen_runs for _,s,_,_ in drafted_texts(r)) else None
    return summary

def write_csv(path,rows):
    if not rows:return
    with open(path,'w',newline='',encoding='utf-8-sig') as f:  # utf-8-sig: Excel opens accents correctly
        w=csv.DictWriter(f,fieldnames=list(rows[0]),delimiter=';');w.writeheader();w.writerows(rows)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('evidence');parser.add_argument('--runs',type=int,default=5)
    parser.add_argument('--model',default='qwen/qwen3-4b-2507');parser.add_argument('--url',default='http://127.0.0.1:1234')
    parser.add_argument('--parallel',type=int,default=3);parser.add_argument('--out')
    args=parser.parse_args(argv)
    data=rebuild(json.load(open(args.evidence,encoding='utf-8')))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=Path(args.out or Path('resultados')/'fidelidad'/f"{data['domain']}-{stamp}");(out/'procedencia').mkdir(parents=True,exist_ok=True)
    baseline=compose_run(data,None)
    claim_rows=claims(baseline,'catálogo',0);run_rows=[run_row(baseline,'catálogo',0)];qwen_runs=[]
    if args.runs>0:
        import llm_client
        config={'provider':'local','url':args.url,'id':args.model,'api_key':''}
        model=llm_client.writer(config,args.parallel)
        print(f"Contexto cargado: {model.context} tokens; redacciones en paralelo: {model.parallel}")
        for warning in model.warnings:print('Aviso:',warning)
        for number in range(1,args.runs+1):
            run=compose_run(data,model);qwen_runs.append(run)
            claim_rows+=claims(run,'qwen',number);run_rows.append(run_row(run,'qwen',number))
            json.dump(run['report_ai'],open(out/'procedencia'/f'ejecucion_{number:02d}.json','w',encoding='utf-8'),ensure_ascii=False,indent=2)
            r=run_rows[-1];print(f"Ejecución {number}/{args.runs}: {r['validadas_ia']}/{r['hallazgos']} validadas, {r['intentos_rechazados']} intentos rechazados, {r['segundos']} s")
    write_csv(out/'afirmaciones.csv',claim_rows);write_csv(out/'ejecuciones.csv',run_rows)
    summary=summarize(claim_rows,run_rows,qwen_runs,baseline)
    summary.update(evidencia=str(args.evidence),modelo=args.model if args.runs else None,ejecuciones_qwen=args.runs)
    json.dump(summary,open(out/'resumen.json','w',encoding='utf-8'),ensure_ascii=False,indent=2)
    print('Resultados en',out)
    return out

if __name__=='__main__':
    sys.exit(0 if main() else 1)
