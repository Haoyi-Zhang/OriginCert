#!/usr/bin/env python3
"""Rebuild scientific results, retaining subprocess logs and actual runner counts."""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any
ROOT=Path(__file__).resolve().parents[1]
RESULTS=ROOT/'results'
STAGE_TIMEOUT_SECONDS=240
sys.dont_write_bytecode=True


def load(path:Path)->dict[str,Any]:
    with path.open(encoding='utf-8') as handle:value=json.load(handle)
    if not isinstance(value,dict):raise ValueError(f'expected object: {path.name}')
    return value


def write(path:Path,value:dict[str,Any])->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name('.'+path.name+'.tmp')
    temp.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    temp.replace(path)


def run_stage(name:str,command:list[str],outputs:list[Path],
              environment:dict[str,str],stages:list[dict[str,Any]])->None:
    begin=time.perf_counter()
    row={'stage':name,'command':command,'exit_code':None,'status':'FAIL'}
    log=''
    log_path=RESULTS/'logs'/f'{name}.txt'
    try:
        for path in outputs:path.unlink(missing_ok=True)
        print(f'[reproduce] {name}',flush=True)
        completed=subprocess.run([sys.executable,'-B',*command],cwd=ROOT,env=environment,
                                 capture_output=True,text=True,timeout=STAGE_TIMEOUT_SECONDS)
        row['exit_code']=completed.returncode
        log=completed.stdout+'\n'+completed.stderr
        if completed.returncode:raise RuntimeError(f'{name} failed; see {log_path}')
        for path in outputs:
            if not path.is_file():raise RuntimeError(f'{name} did not write {path.name}')
            if path.suffix=='.json' and load(path).get('status')!='PASS':
                raise RuntimeError(f'{name}: {path.name} did not report PASS')
        row['status']='PASS'
    except subprocess.TimeoutExpired as error:
        def decoded(value:Any)->str:
            return value.decode('utf-8',errors='replace') if isinstance(value,bytes) else (value or '')
        log=decoded(error.stdout)+'\n'+decoded(error.stderr)
        row.update(status='TIMEOUT',timeout_seconds=STAGE_TIMEOUT_SECONDS)
        row['error']=f'{name} exceeded its time budget'
        raise RuntimeError(row['error']) from error
    except Exception as error:
        row['error']=str(error)
        raise
    finally:
        row['elapsed_seconds']=round(time.perf_counter()-begin,6)
        row['log']=f'logs/{name}.txt'
        stages.append(row)
        log_path.parent.mkdir(parents=True,exist_ok=True)
        log_path.write_text((log+'\n'+str(row.get('error',''))+'\n').replace(str(ROOT)+os.sep,''),
                            encoding='utf-8')


def main()->int:
    if sys.version_info<(3,10):raise SystemExit('CPython 3.10 or later is required')
    if not sys.platform.startswith('linux'):
        raise SystemExit('The retained resource measurements and runner require Linux (resource RSS in KiB).')
    import resource
    started=time.perf_counter()
    stages=[]
    environment=dict(os.environ)
    environment['PYTHONDONTWRITEBYTECODE']='1'
    environment['PYTHONUTF8']='1'
    environment['PYTHONPATH']=str(ROOT)
    def run(name:str,command:list[str],outputs:list[Path])->None:
        run_stage(name,command,outputs,environment,stages)
    try:
        run('core',['scripts/reproduce_core.py'],[])
        run('backend',['scripts/backend_roundtrip.py','--cases','data/cases','--output','results/backend_roundtrip.json'],[RESULTS/'backend_roundtrip.json'])
        run('stress',['scripts/differential_stress.py','--output','results/differential_stress.json'],[RESULTS/'differential_stress.json'])
        run('scaling',['scripts/scaling_study.py','--cases','data/cases','--output-json','results/scaling_study.json','--output-csv','results/scaling_study.csv'],[RESULTS/'scaling_study.json',RESULTS/'scaling_study.csv'])
        run('metamorphic',['scripts/metamorphic_suite.py','--output','results/metamorphic_suite.json'],[RESULTS/'metamorphic_suite.json'])
        run('journal',['scripts/journal_validation.py','--output','results/journal_validation.json'],[RESULTS/'journal_validation.json'])
        for name,script,report in [('code','audit_code.py','code-quality-audit.json'),
                                   ('formal','audit_formal_alignment.py','formal-alignment-audit.json'),
                                   ('design','audit_experimental_design.py','experimental-design-audit.json')]:
            run(name,['scripts/'+script],[ROOT/'audit'/report])
        summary=load(RESULTS/'summary.json')
        backend=load(RESULTS/'backend_roundtrip.json');stress=load(RESULTS/'differential_stress.json')
        scaling=load(RESULTS/'scaling_study.json');meta=load(RESULTS/'metamorphic_suite.json')
        journal=load(RESULTS/'journal_validation.json');tests=load(RESULTS/'test_results.json')
        summary['independent_validation']={
            'reference_backend_roundtrips':backend['roundtrips'],
            'reference_backend_assignments':backend['assignments'],
            'reference_backend_count':len(backend['backends']),
            'stress_seed_count':stress['seed_count'],'stress_cases':stress['cases'],
            'stress_assignments':stress['assignments'],'scaling_rows':len(scaling['rows']),
            'metamorphic_records':meta['transformed_records'],
            'journal_certificates':journal['certificates'],
            'journal_pointwise_inputs':journal['concrete_inputs_compared'],
            'certificate_checker_enumerates_assignments':False}
        elapsed=time.perf_counter()-started
        peak=max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                 resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        summary['performance']['complete_reproduction_wall_seconds']=round(elapsed,6)
        summary['performance']['complete_reproduction_peak_rss_kib']=int(peak)
        summary['correctness']['contract_tests_run']=tests['tests_run']
        summary['correctness']['contract_tests_passed']=tests['tests_run']-tests['failures']-tests['errors']-tests['skipped']
        write(RESULTS/'summary.json',summary)
        report={'status':'PASS','environment':{'python_implementation':platform.python_implementation(),
                  'python':platform.python_version(),'os':platform.system(),'rss_unit':'KiB',
                  'workers':1},'stages':stages,'tests_run':tests['tests_run'],
                'elapsed_seconds':round(elapsed,6),'peak_rss_kib':int(peak),
                'scope':'Scientific reproduction. Paper compilation and reference-content checks are separate.'}
        write(RESULTS/'reproduction.json',report)
        print(f'Complete reproduction PASS: {tests["tests_run"]} tests, {elapsed:.3f} s',flush=True)
        return 0
    except Exception as error:
        write(RESULTS/'reproduction.json',{'status':'FAIL','stages':stages,'error':str(error)})
        raise
if __name__=='__main__':raise SystemExit(main())
