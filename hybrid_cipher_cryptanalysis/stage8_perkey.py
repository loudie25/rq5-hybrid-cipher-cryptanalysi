import numpy as np, json, math
import construction_b as B
from stage8_heldout import sample, keyS
from stage8_trail_dp import run
rows=[]
for n,st,m in [(2,(0x20,0x20),1<<22),(3,(0x20,0x20),1<<23),(4,(0x20,0x20),1<<24),(5,(0x20,0x20),1<<25)]:
    rng=np.random.default_rng(700+n); tops=[]
    for k in range(20,26):
        d=np.concatenate([sample(keyS(k),st,n,1<<22,rng) for _ in range(max(1,m>>22))]) if m>=1<<22 else None
        u,c=np.unique(d,return_counts=True); tops.append(math.log2(c.max()/len(d)))
    dp=run(st,n,20000)[n]['max_p']
    rows.append(dict(rounds=n,start=hex(st[0]),pmax_log2_per_key=[round(x,2) for x in tops],mean=round(float(np.mean(tops)),2),dp_keyavg_log2=round(math.log2(dp),2)))
    print(rows[-1],flush=True)
json.dump(rows,open("results/stage8_perkey_results.json","w"),indent=1)
