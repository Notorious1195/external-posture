"""Earlier version scripts (test_v*.py) patch module globals such as streamlit or backend, so each runs isolated."""
import os,subprocess,sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=sorted(p.name for p in ROOT.glob('test_*.py'))

@pytest.mark.parametrize('script',SCRIPTS)
def test_script(script):
    run=subprocess.run([sys.executable,script],cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=900,
                       env={**os.environ,'PYTHONUTF8':'1','PYTHONIOENCODING':'utf-8'})
    output=run.stdout+run.stderr
    assert run.returncode==0 and 'FAILED' not in output,output[-4000:]
