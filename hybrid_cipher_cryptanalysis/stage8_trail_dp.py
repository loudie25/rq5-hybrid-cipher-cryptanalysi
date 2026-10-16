"""Stage 8: exact trail DP for the XOR-keyed RC5 core (Construction B, Eq. 4 as published).
Model (Markov-cipher assumption, data random, XOR key masks uniform):
  half-round A: L1 = rotl(L^R, R mod 32) ^ k ; half-round B: R1 = rotl(R^L1, L1 mod 32) ^ k'
Difference propagates deterministically given the rotation amount iff the difference of the word
supplying the amount has low 5 bits == 0; amount is uniform over 0..31 independent of everything
else (masked by a uniform key). Otherwise the pair is 'lost' (treated as random: attacker gets 0),
so every probability below is a LOWER BOUND on attacker success."""
import numpy as np

M = np.uint64(0xFFFFFFFF)
def rotl_v(x, r):  # x uint64 array of 32-bit values, r int
    x = x.astype(np.uint64)
    r = np.uint64(r)
    return ((x << r) | (x >> (np.uint64(32) - r))) & M if r else x

def step(states, probs, half, K):
    """states: uint64 array dL<<32|dR ; half 'A' or 'B'. Returns merged (states, probs, lost_mass)."""
    dL = (states >> np.uint64(32)) & M
    dR = states & M
    if half == 'A':
        ok = (dR & np.uint64(31)) == 0
        base = dL ^ dR
    else:
        ok = (dL & np.uint64(31)) == 0       # dL here is L1
        base = dR ^ dL
    lost = probs[~ok].sum()
    dL, dR, base, p = dL[ok], dR[ok], base[ok], probs[ok]
    outs, ps = [], []
    for r in range(32):
        rot = rotl_v(base, r)
        if half == 'A':
            outs.append((rot << np.uint64(32)) | dR)
        else:
            outs.append((dL << np.uint64(32)) | rot)
        ps.append(p / 32.0)
    o = np.concatenate(outs); pp = np.concatenate(ps)
    u, inv = np.unique(o, return_inverse=True)
    agg = np.zeros(len(u)); np.add.at(agg, inv, pp)
    if len(u) > K:
        idx = np.argpartition(-agg, K)[:K]
        u, agg = u[idx], agg[idx]
    return u, agg, lost

def run(start, rounds=12, K=20000):
    """start = (dL, dR) post-whitening. Returns per-round dict: max single output-difference prob,
    surviving mass, and the top output state."""
    s = np.array([(start[0] << 32) | start[1]], dtype=np.uint64); p = np.array([1.0])
    res = {}
    for rd in range(1, rounds + 1):
        s, p, _ = step(s, p, 'A', K)
        s, p, _ = step(s, p, 'B', K)
        if len(p) == 0: res[rd] = dict(max_p=0.0, mass=0.0, top=None); continue
        j = int(np.argmax(p))
        res[rd] = dict(max_p=float(p[j]), mass=float(p.sum()), top=(int(s[j] >> np.uint64(32)), int(s[j] & M)))
    return res

if __name__ == "__main__":
    import json, math, sys
    starts = []
    for q in range(32): starts.append((1 << q, 0))                       # single bit in L
    for p_ in range(5, 32): starts.append((0, 1 << p_))                  # single bit in R (low5 must be 0)
    for p_ in range(5, 32): starts.append((1 << p_, 1 << p_))            # equal bits (u = 0)
    for q in range(32):
        for p_ in (5, 16, 31): starts.append((1 << q, 1 << p_))
    best = {rd: (0.0, None) for rd in range(1, 13)}
    bestmass = {rd: (0.0, None) for rd in range(1, 13)}
    for st in starts:
        r = run(st, 12, int(__import__("os").environ.get("S8_K", "40000")))
        for rd in range(1, 13):
            if r[rd]['max_p'] > best[rd][0]: best[rd] = (r[rd]['max_p'], st, r[rd]['top'])
            if r[rd]['mass'] > bestmass[rd][0]: bestmass[rd] = (r[rd]['mass'], st)
    out = {}
    for rd in range(1, 13):
        out[rd] = dict(best_single_diff_prob=best[rd][0], log2=(math.log2(best[rd][0]) if best[rd][0] > 0 else None),
                       start=best[rd][1] and [hex(best[rd][1][0]), hex(best[rd][1][1])],
                       top_out=best[rd][2] and [hex(best[rd][2][0]), hex(best[rd][2][1])],
                       best_survival_mass=bestmass[rd][0], survival_start=bestmass[rd][1] and [hex(bestmass[rd][1][0]), hex(bestmass[rd][1][1])])
        print(rd, out[rd]['log2'], out[rd]['start'], out[rd]['top_out'], round(bestmass[rd][0], 6), flush=True)
    json.dump(out, open("results/stage8_dp_results.json", "w"), indent=1)
