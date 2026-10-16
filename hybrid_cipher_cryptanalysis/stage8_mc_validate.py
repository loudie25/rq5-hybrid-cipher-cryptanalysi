import numpy as np, random, json, math, sys
import construction_b as B
from stage8_trail_dp import run

U = np.uint32
def rotl_vec(x, r):
    r = (r & 31).astype(np.uint32)
    return ((x << r) | (x >> ((np.uint32(32) - r) & np.uint32(31)))) & U(0xFFFFFFFF) if False else (np.where(r == 0, x, (x << r) | (x >> (np.uint32(32) - r)))).astype(np.uint32)

def core_rounds_vec(L, R, S, n):
    """vectorised B.round_function_forward_nrounds followed by output whitening"""
    for i in range(1, n + 1):
        L = rotl_vec(L ^ R, R & U(31)) ^ U(S[2 * i])
        R = rotl_vec(R ^ L, L & U(31)) ^ U(S[2 * i + 1])
    return L ^ U(S[2 * n]), R ^ U(S[2 * n + 1])

def selftest():
    rng = random.Random(1)
    key = bytes(rng.randrange(256) for _ in range(16)); S = B.rc5_key_expansion(key)
    for n in (1, 3, 12):
        for _ in range(200):
            L, R = rng.getrandbits(32), rng.getrandbits(32)
            l, r = B.round_function_forward_nrounds(L, R, S, n)
            l ^= S[2 * n]; r ^= S[2 * n + 1]
            vl, vr = core_rounds_vec(np.array([L], U), np.array([R], U), S, n)
            assert (int(vl[0]), int(vr[0])) == (l & 0xFFFFFFFF, r & 0xFFFFFFFF)
    return True

def mc(start, target, n, pairs, keys=4, seed=7):
    """empirical Pr[ output diff == target ] for post-whitening input diff `start` after n rounds"""
    rng = np.random.default_rng(seed); hits = 0; total = 0
    for k in range(keys):
        key = bytes(rng.integers(0, 256, 16, dtype=np.uint8)); S = B.rc5_key_expansion(key)
        per = pairs // keys; chunk = 1 << 21
        for off in range(0, per, chunk):
            m = min(chunk, per - off)
            L = rng.integers(0, 2**32, m, dtype=np.uint64).astype(U); R = rng.integers(0, 2**32, m, dtype=np.uint64).astype(U)
            a = core_rounds_vec(L, R, S, n); b = core_rounds_vec(L ^ U(start[0]), R ^ U(start[1]), S, n)
            hits += int(((a[0] ^ b[0]) == U(target[0])).__and__((a[1] ^ b[1]) == U(target[1])).sum()); total += m
    return hits, total

if __name__ == "__main__":
    print("vector == scalar core:", selftest())
    # DP-predicted best differential per round, MC-validated where p is large enough
    rows = []
    cands = {1: (0, 0x20), 2: (0x20, 0x20), 3: (0x1, 0), 4: (0x20, 0x20), 5: (0x20, 0x20)}
    pairs_for = {1: 1 << 20, 2: 1 << 22, 3: 1 << 24, 4: 1 << 25, 5: 1 << 26}
    for n, st in cands.items():
        r = run(st, n, 20000)[n]
        hits, tot = mc(st, r['top'], n, pairs_for[n])
        pred = r['max_p']; emp = hits / tot
        se = math.sqrt(max(hits, 1)) / tot
        rows.append(dict(rounds=n, start=[hex(st[0]), hex(st[1])], target=[hex(r['top'][0]), hex(r['top'][1])], dp_prob=pred, dp_log2=math.log2(pred),
                         mc_hits=hits, mc_pairs=tot, mc_prob=emp, mc_log2=(math.log2(emp) if emp else None), ratio=emp / pred, z=(emp - pred) / se if hits else None))
        print(rows[-1], flush=True)
    json.dump(rows, open("results/stage8_mc_results.json", "w"), indent=1)
