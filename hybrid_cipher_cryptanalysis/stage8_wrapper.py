"""Wrapper model (Li, Xiao, Feng): block-index-fixed byte permutation (pre) + XOR mask (post), around the real core.
Both depend only on (chaotic stream, block index m), never on plaintext, so for a pair encrypted at the same m they are constants."""
import numpy as np, json, math
import construction_b as B
from stage8_mc_validate import core_rounds_vec, U
N = 3
rng = np.random.default_rng(5)
key = bytes(rng.integers(0,256,16,dtype=np.uint8)); S = B.rc5_key_expansion(key)
perm = rng.permutation(8); mask = rng.integers(0,256,8,dtype=np.uint8)   # unknown to attacker
def words(by):  # (m,8) uint8 -> L,R uint32 big endian
    b = by.astype(np.uint32); L = (b[:,0]<<24)|(b[:,1]<<16)|(b[:,2]<<8)|b[:,3]; R = (b[:,4]<<24)|(b[:,5]<<16)|(b[:,6]<<8)|b[:,7]; return L, R
def enc(by, wrap):
    if wrap: sc = np.empty_like(by); sc[:, perm] = by; by = sc            # scrambled[perm[i]] = pt[i]
    L, R = words(by)
    L = ((L ^ U(S[0])) + U(1)).astype(U); R = ((R ^ U(S[1])) + U(2)).astype(U)   # published whitening
    L, R = core_rounds_vec(L, R, S, N)
    out = np.stack([(L>>24)&255,(L>>16)&255,(L>>8)&255,L&255,(R>>24)&255,(R>>16)&255,(R>>8)&255,R&255],1).astype(np.uint8)
    return out ^ mask if wrap else out
def trial(diff_bytes, wrap, m=1<<22, seed=1):
    r = np.random.default_rng(seed); hits = 0; tot = 0
    for _ in range(m >> 21):
        P = r.integers(0,256,(1<<21,8),dtype=np.uint8); Q = P ^ np.array(diff_bytes, dtype=np.uint8)
        d = enc(P, wrap) ^ enc(Q, wrap)
        hits += int((d == TARGET).all(1).sum()); tot += 1<<21
    return hits, tot
# best 3-round start from the heavy-hitter run: post-whitening (dL,dR) = (0x20,0x20) -> (0x8000,0x80000000)
def dbytes(dl, dr): return list(dl.to_bytes(4,'big') + dr.to_bytes(4,'big'))
TARGET = np.array(dbytes(0x8000, 0x80000000), dtype=np.uint8)
D = dbytes(0x20, 0x20)
inv = np.argsort(perm)                       # attacker who knows perm: place diff so that scrambled diff == D
Dk = [0]*8
for i in range(8): Dk[i] = D[perm[i]]        # scrambled[perm[i]] = pt[i]  => pt diff byte i = D[perm[i]]
res = {}
for name, d, wrap in [("no wrapper", D, False), ("wrapper, attacker knows permutation", Dk, True), ("wrapper, attacker ignores it", D, True)]:
    h, t = trial(d, wrap); res[name] = dict(hits=h, pairs=t, p=h/t, log2=(math.log2(h/t) if h else None)); print(name, res[name], flush=True)
# number of distinct input differences attacker must try (positions of the 2 active bytes after an unknown byte permutation)
res["candidates_for_two_active_bytes"] = 8*7
json.dump(res, open("results/stage8_wrapper_results.json","w"), indent=1)
