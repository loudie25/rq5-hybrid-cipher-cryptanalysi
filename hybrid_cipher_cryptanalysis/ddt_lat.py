"""Stage 4: exact DDT / LAT of Construction A's byte-wise addition primitive,
plus the validated carry-pair DP for n-bit addition (used for Construction B's
32-bit whitening stage)."""
import numpy as np

N = 256


def build_ddt():
    """ddt[d_in][d_out] = count over all 65536 (a,k) pairs."""
    ddt = np.zeros((N, N), dtype=np.int64)
    a = np.arange(N, dtype=np.int64)
    for d in range(N):
        ap = a ^ d
        for k in range(N):
            ddt[d] += np.bincount(((a + k) % N) ^ ((ap + k) % N), minlength=N)
    return ddt


def build_lat():
    """Returns (expected_abs_corr[alpha,beta], signed_corr_by_k[k,alpha,beta])."""
    a = np.arange(N, dtype=np.int64)
    idx = np.arange(N, dtype=np.uint16)
    pc = np.vectorize(lambda x: bin(int(x)).count("1"))(np.bitwise_and.outer(idx, idx))
    H = np.where(pc % 2 == 0, 1.0, -1.0)
    signed = np.zeros((N, N, N))
    for k in range(N):
        signed[k] = (H @ H[(a + k) % N, :]) / N
    return np.abs(signed).mean(axis=0), signed


def edp_add(alpha, gamma, n):
    """Exact EDP of n-bit modular addition with a shared uniform operand,
    via a 4-state carry-pair automaton (validated against build_ddt at n=8)."""
    states = {(0, 0): 1.0}
    for i in range(n):
        ai, gi = (alpha >> i) & 1, (gamma >> i) & 1
        new = {}
        for (c1, c2), p in states.items():
            for x in (0, 1):
                for k in (0, 1):
                    s1 = x ^ k ^ c1
                    n1 = (x & k) | (x & c1) | (k & c1)
                    x2 = x ^ ai
                    s2 = x2 ^ k ^ c2
                    n2 = (x2 & k) | (x2 & c2) | (k & c2)
                    if (s1 ^ s2) != gi:
                        continue
                    new[(n1, n2)] = new.get((n1, n2), 0.0) + p * 0.25
        states = new
        if not states:
            return 0.0
    return sum(states.values())


def validate_dp_against_ddt(ddt):
    """Returns number of mismatches over all 65536 (alpha,gamma) pairs at n=8."""
    bad = 0
    for al in range(N):
        for ga in range(N):
            if abs(edp_add(al, ga, 8) - ddt[al][ga] / 65536.0) > 1e-9:
                bad += 1
    return bad
