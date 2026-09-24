from __future__ import annotations
import copy, json, random, sys
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.core import validate_case, canonical_assignments, execute_concrete_evidence, analyze_events, symbolic_paths, cube_assignments, canonical_json
from src.certify import make_result
from checker.check import verify, emitted, replay, classify_case

R=random.Random(0x5EED2027)
CAT={"obligations":[
 {"id":"sql-safe","trigger":{"op":"sink","channel":"sql"},"rule":{"kind":"protection","requires":["sql_parameter"]}},
 {"id":"html-safe","trigger":{"op":"sink","channel":"html"},"rule":{"kind":"protection","requires":["html_escape"]}},
 {"id":"auth-checked","trigger":{"op":"privileged"},"rule":{"kind":"preceded","capability_field":"capability"}},
 {"id":"token-strong","trigger":{"op":"token"},"rule":{"kind":"strong_rng","source_field":"source"}},
 {"id":"no-shell","trigger":{"op":"sink","channel":"shell"},"rule":{"kind":"forbid","message":"shell sink forbidden"}},
]}
EVENTS=[
 ({"op":"source","target":"raw"},[]),
 ({"op":"source","target":"query"},[]),
 ({"op":"protect","target":"query","source":"raw","protection":"sql_parameter"},[]),
 ({"op":"protect","target":"query","source":"raw","protection":"html_escape"},[]),
 ({"op":"protect","target":"alias","source":"nonce","protection":"tag"},[]),
 ({"op":"sink","channel":"sql","source":"query"},["sql-safe"]),
 ({"op":"sink","channel":"html","source":"query"},["html-safe"]),
 ({"op":"sink","channel":"shell","source":"raw"},["no-shell"]),
 ({"op":"check","capability":"admin"},[]),
 ({"op":"privileged","capability":"admin"},["auth-checked"]),
 ({"op":"rng","target":"nonce","strength":"strong"},[]),
 ({"op":"rng","target":"nonce","strength":"weak"},[]),
 ({"op":"token","source":"nonce"},["token-strong"]),
 ({"op":"token","source":"alias"},["token-strong"]),
 ({"op":"noop"},[]),
]

def same(a,b): return canonical_json(a)==canonical_json(b)
def reqs(event):
 return sorted(o['id'] for o in CAT['obligations'] if all(k in event and same(event[k],v) for k,v in o['trigger'].items()))
def oracle(events, emitters):
 p={}; c=set(); s=set(); fails=[]
 by={o['id']:o for o in CAT['obligations']}
 for i,e in enumerate(events):
  if e['origin']!=emitters[i]: fails.append(('origin',None,i))
  required=reqs(e)
  if sorted(e['obligations'])!=required: fails.append(('coverage', required[0] if required else None,i))
  for oid in required:
   r=by[oid]['rule']; k=r['kind']; bad=False
   if k=='protection': bad=not set(r['requires']).issubset(p.get(e.get(r.get('source_field','source')),set()))
   elif k=='preceded': bad=e.get(r.get('capability_field','capability')) not in c
   elif k=='strong_rng': bad=e.get(r.get('source_field','source')) not in s
   elif k=='forbid': bad=True
   if bad: fails.append(('safety',oid,i))
  op=e['op']
  if op=='source': p[e['target']]=set(); s.discard(e['target'])
  elif op=='protect':
   strong=e['source'] in s; p[e['target']]=set(p.get(e['source'],set()))|{e['protection']}
   if strong: s.add(e['target'])
   else: s.discard(e['target'])
  elif op=='check': c.add(e['capability'])
  elif op=='rng':
   p[e['target']]=set()
   if e['strength']=='strong': s.add(e['target'])
   else: s.discard(e['target'])
 return fails

def norm_fails(fs): return [(x['kind'],x['obligation'],x['event_index']) for x in fs]

def mkcase(i):
 counter=0
 def nid(prefix):
  nonlocal counter; counter+=1; return f'{prefix}-{counter}'
 def emit():
  e,obs=R.choice(EVENTS); n={'node':nid('emit'),'kind':'emit','event':copy.deepcopy(e)}
  if obs: n['declared_obligations']=list(obs)
  return n
 def tree(d):
  if d<=0 or R.random()<0.38: return emit()
  kind=R.choice(['seq','ifflag','ifmode','repeat'])
  if kind=='seq': return {'node':nid('seq'),'kind':'seq','children':[tree(d-1) for _ in range(R.randint(1,3))]}
  if kind=='ifflag': return {'node':nid('if'),'kind':'if','condition':{'field':'flag','equals':R.choice([False,True])},'then':tree(d-1),'else':tree(d-1)}
  if kind=='ifmode': return {'node':nid('if'),'kind':'if','condition':{'field':'mode','equals':R.choice([1,True])},'then':tree(d-1),'else':tree(d-1)}
  return {'node':nid('repeat'),'kind':'repeat','count_field':'count','body':tree(d-1)}
 g=tree(R.randint(1,4))
 # Occasionally inject an evidence-only defect, choosing an emit deterministically.
 emits=[]
 def collect(n):
  if n['kind']=='emit': emits.append(n)
  elif n['kind']=='seq':
   for x in n['children']: collect(x)
  elif n['kind']=='if': collect(n['then']); collect(n['else'])
  else: collect(n['body'])
 collect(g)
 if emits and R.random()<0.35:
  n=R.choice(emits)
  if R.random()<0.5: n['origin_override']='nonexistent-node'
  else:
   ds=list(n.get('declared_obligations',[]))
   if ds: n['declared_obligations']=[]
   else: n['declared_obligations']=['sql-safe']
 return {'case_id':f'stress-{i}','family':'stress','schema':{'fields':[
  {'name':'flag','domain':[False,True]}, {'name':'mode','domain':[1,True]}, {'name':'count','domain':[0,1,2]}]},
  'catalog':copy.deepcopy(CAT),'generator':g}

def main() -> None:
 N=600
 assignments=0
 certs=0
 for i in range(N):
  case=mkcase(i); validate_case(case)
  result=make_result(case); verify(case,result)
  certs += result['kind']=='certificate'
  expect='accepted' if result['kind']=='certificate' else 'rejected'
  if classify_case(case)!=expect: raise AssertionError(('classification',i))
  # Symbolic partition must cover each JSON-distinct assignment once.
  seen=[]
  for cube,_,_ in symbolic_paths(case): seen.extend(cube_assignments(case['schema'],cube))
  canon=[canonical_json(x) for x in seen]
  target=[canonical_json(x) for x in canonical_assignments(case['schema'])]
  if sorted(canon)!=sorted(target) or len(canon)!=len(set(canon)): raise AssertionError(('partition',i))
  for a in canonical_assignments(case['schema']):
   assignments+=1
   ev,em=execute_concrete_evidence(case['generator'],a); st,fl=analyze_events(case['catalog'],em,ev)
   cev,cem=emitted(case['generator'],a); cst,cfl=replay(case['catalog'],cem,cev)
   if (ev,em,st,fl)!=(cev,cem,cst,cfl): raise AssertionError(('dual',i,a))
   if norm_fails(fl)!=oracle(ev,em): raise AssertionError(('oracle',i,a,norm_fails(fl),oracle(ev,em)))
 print(json.dumps({'cases':N,'assignments':assignments,'certificates':certs,'counterexamples':N-certs,'status':'PASS'},sort_keys=True))

if __name__ == "__main__":
 main()
