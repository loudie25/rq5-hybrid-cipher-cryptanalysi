"""Stage 5: exact trail chaining for Construction A.

Key structural fact (verified empirically by run_all.py): the 8 byte lanes of
the Feistel network never mix, so each lane is an independent single-byte
Feistel network sharing one DDT/LAT. Per-lane state (dL, dR) has 65536 states
and is propagated exactly (Markov chain), not sampled.

Feistel recursion (matches construction_a.feistel_encrypt_block):
  differential: dL' = dR ; dR' = dL xor dOut,  dOut ~ DDT[dR]
  linear      : beta = GL ; GR' = GL ; GL' = GR xor alpha ; corr *= corr(alpha,beta;K)
The cipher's final L,R swap is NOT included in these internal states."""
import numpy as np

N = 256


def single_path_diff(ddt_prob, dl0, dr0, n_rounds):
    dl, dr, prob = dl0, dr0, 1.0
    states = [(dl, dr)]
    for _ in range(n_rounds):
        row = ddt_prob[dr]
        dout = int(np.argmax(row))
        prob *= row[dout]
        dl, dr = dr, dl ^ dout
        states.append((dl, dr))
    return states, prob


def exact_markov_diff(ddt_prob, dl0, dr0, n_rounds):
    """Exact distribution over (dL,dR) after n_rounds from a point mass."""
    a = np.arange(N)
    xt = a[:, None] ^ a[None, :]
    P = np.zeros((N, N))
    P[dl0, dr0] = 1.0
    for _ in range(n_rounds):
        new = np.zeros((N, N))
        for r in range(N):
            col = P[:, r]
            if col.any():
                new[r, :] = col @ ddt_prob[r][xt]
        P = new
    return P


def mask_sequence(expected_abs_corr, gl0, gr0, n_rounds):
    gl, gr = gl0, gr0
    states, steps = [(gl, gr)], []
    for _ in range(n_rounds):
        beta = gl
        alpha = int(np.argmax(expected_abs_corr[:, beta]))
        steps.append((alpha, beta, float(expected_abs_corr[alpha, beta])))
        gl, gr = gr ^ alpha, beta
        states.append((gl, gr))
    return states, steps


def exact_sign(signed_corr_by_k, steps, subkey_bytes):
    s = 1.0
    for (alpha, beta, _), k in zip(steps, subkey_bytes):
        s *= signed_corr_by_k[k, alpha, beta]
    return s
