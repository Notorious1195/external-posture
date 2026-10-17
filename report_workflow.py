"""Idempotent automatic report preparation, with bounded retries on re-entry."""
from report_context import signature

def ensure(data,prepare,progress):
    current=signature(data)
    state=data.get('report_preparation',{})
    if state.get('signature')==current and (state.get('complete') or state.get('attempts',0)>=3):return False
    attempts=state.get('attempts',0)+1 if state.get('signature')==current else 1
    progress.write('Preparando evidencias, contexto y documento automáticamente…')
    try:
        prepare(data,progress)
        ai=data.get('report_ai',{})
        complete=ai.get('status') in ('OK','REGLAS') and not data.get('visual_errors')
        data['report_preparation']={'signature':signature(data),'complete':complete,'attempts':attempts,'status':'LISTO' if complete else 'PARCIAL'}
    except Exception as exc:
        data['report_preparation']={'signature':current,'complete':False,'attempts':attempts,'status':'PARCIAL','error':type(exc).__name__+': preparación no completada'}
        raise
    return True
