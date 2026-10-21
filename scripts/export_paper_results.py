#!/usr/bin/env python3
"""Export a selected successful run and freshly render its paper plots.

Default retained mode preserves the strict published CSV snapshot check.
Use --mode selected-run --results-dir PATH for intentional new-run exports.
This paper-only command does not run an experiment or compile TeX.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--paper-dir',type=Path,required=True)
    parser.add_argument('--results-dir',type=Path,default=ROOT/'results')
    parser.add_argument('--mode',choices=('retained','selected-run'),default='retained')
    args=parser.parse_args()
    paper=args.paper_dir.resolve()
    # A failed attempt must not leave cached PDFs available as apparent success.
    for name in ('main.pdf','figures/recall.pdf','figures/scaling.pdf'):
        (paper/name).unlink(missing_ok=True)
    if not (paper/'figures/draw_evaluation.py').is_file():
        raise ValueError('The destination must contain the paper CSV renderer')
    spec=importlib.util.spec_from_file_location('paper_evaluation_data',paper/'figures/evaluation_data.py')
    data=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(data)
    summary=data.load_json(args.results_dir/'summary.json')
    reproduction=data.load_json(args.results_dir/'reproduction.json')
    tests=data.load_json(args.results_dir/'test_results.json')
    values=data.export_values(summary,reproduction,tests)
    text='% Numerical values exported from one successful retained scientific run.\n'
    for key,value in values.items():
        text+='\\newcommand{\\'+key+'}{'+value+'}\n'
    # Do not publish changed numbers until both real plots have succeeded.
    with tempfile.TemporaryDirectory(prefix='paper-export-',dir=paper) as directory:
        stage=Path(directory)
        (stage/'figures').mkdir()
        (stage/'results.tex').write_text(text,encoding='utf-8',newline='')
        (stage/'summary.json').write_text(json.dumps(summary,allow_nan=False),encoding='utf-8')
        shutil.copyfile(args.results_dir/'scaling_study.csv',stage/'scaling.csv')
        (stage/'figures/recall.csv').write_text(data.recall_csv(summary),encoding='utf-8',newline='')
        command=[sys.executable,*(['-S'] if sys.flags.no_site else []),'-B',str(paper/'figures/draw_evaluation.py'),
                 '--mode',args.mode,'--data-dir',str(stage),'--output-dir',str(stage/'figures'),
                 '--summary',str(stage/'summary.json')]
        subprocess.run(command,check=True)
        for name in ('results.tex','scaling.csv','figures/recall.csv','figures/recall.pdf','figures/scaling.pdf'):
            (stage/name).replace(paper/name)
    print(json.dumps({'status':'PASS','mode':args.mode,'values':values,'plots_freshly_rendered':True},indent=2))

if __name__=='__main__':
    main()
