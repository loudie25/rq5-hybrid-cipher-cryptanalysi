import numpy as np, json, math
import construction_b as B
from stage8_mc_validate import core_rounds_vec, U
from stage8_trail_dp import run
def sample(S, st, n, m, rng):
    L=rng.integers(0,2**32,m,dtype=np.uint64).astype(U);R=rng.integers(0,2**32,m,dtype=np.uint64).astype(U)
    a=core_rounds_vec(L,R,S,n);b=core_rounds_vec(L^U(st[0]),R^U(st[1]),S,n)
    return ((a[0]^b[0]).astype(np.uint64)<<np.uint64(32))|(a[1]^b[1]).astype(np.uint64)
def keyS(seed):
    r=np.random.default_rng(seed); return B.rc5_key_expansion(bytes(r.integers(0,256,16,dtype=np.uint8)))
if __name__=="__main__":
    rows=[]
    for n,st,m in [(2,(0x0,0x20),1<<22),(3,(0x20,0x20),1<<24),(3,(0x1,0),1<<24),(4,(0x20,0x20),1<<25),(4,(0x0,0x400),1<<25)]:
        rng=np.random.default_rng(900+n)
        # discovery key
        d=np.concatenate([sample(keyS(1),st,n,1<<22,rng) for _ in range(m>>22)])
        u,c=np.unique(d,return_counts=True); tgt=int(u[np.argmax(c)])
        # held-out keys
        ps=[]
        for k in range(2,10):
            h=0;t=0
            for _ in range(m>>22):
                x=sample(keyS(k),st,n,1<<22,rng); h+=int((x==np.uint64(tgt)).sum()); t+=1<<22
            ps.append(h/t)
        avg=float(np.mean(ps)); dp=run(st,n,20000)[n]
        rows.append(dict(rounds=n,start=[hex(st[0]),hex(st[1])],target=[hex(tgt>>32),hex(tgt&0xFFFFFFFF)],heldout_mean_log2=math.log2(avg) if avg else None,
            heldout_min_log2=math.log2(min(ps)) if min(ps) else None,heldout_max_log2=math.log2(max(ps)) if max(ps) else None,dp_max_log2=math.log2(dp['max_p']),
            discovery_log2=math.log2(c.max()/(m))))
        print(rows[-1],flush=True)
    json.dump(rows,open("results/stage8_heldout_results.json","w"),indent=1)
