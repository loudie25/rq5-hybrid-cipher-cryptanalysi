"""Stage 5: Monte Carlo validation against the real reimplementations."""
import random
import numpy as np
from construction_a import key_schedule, feistel_encrypt_block_nrounds
from construction_b import (rc5_key_expansion, rc5_core_encrypt_block_nrounds,
                            PUBLISHED_EXAMPLE_KEY)
from trails import mask_sequence, exact_sign


def _rb(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def parity(v, m):
    return bin(v & m).count("1") % 2


def a_differential(trials, rounds, rng, internal_states):
    """Lane-0 start (dL=0,dR=0x80). internal_states[n] = predicted internal
    (dL,dR); ciphertext difference is the swapped pair (final L,R swap)."""
    res = {}
    for n in rounds:
        dl, dr = internal_states[n]
        want = (dr, dl)
        bad = 0
        for _ in range(trials):
            subkeys = key_schedule(_rb(rng, 16))
            base = _rb(rng, 16)
            p = bytearray(base)
            p[8] ^= 0x80
            c1 = feistel_encrypt_block_nrounds(base, subkeys, n)
            c2 = feistel_encrypt_block_nrounds(bytes(p), subkeys, n)
            d = bytes(x ^ y for x, y in zip(c1, c2))
            clean = all(d[i] == 0 for i in range(16) if i not in (0, 8))
            if (d[0], d[8]) != want or not clean:
                bad += 1
        res[n] = {"trials": trials, "mismatches": bad}
    return res


def a_lane_independence(trials, rng, internal_states):
    dl, dr = internal_states[16]
    want = (dr, dl)
    bad = 0
    for _ in range(trials):
        subkeys = key_schedule(_rb(rng, 16))
        base = _rb(rng, 16)
        p = bytearray(base)
        p[8] ^= 0x80
        p[11] ^= 0x80
        c1 = feistel_encrypt_block_nrounds(base, subkeys, 16)
        c2 = feistel_encrypt_block_nrounds(bytes(p), subkeys, 16)
        d = bytes(x ^ y for x, y in zip(c1, c2))
        ok = ((d[0], d[8]) == want and (d[3], d[11]) == want and
              all(d[i] == 0 for i in range(16) if i not in (0, 8, 3, 11)))
        bad += (not ok)
    return {"trials": trials, "mismatches": bad}


def a_linear_multikey(n_keys, trials, rounds, rng, expected_abs_corr, signed):
    """For each random key and round count: predict the constant bit from the
    real subkey parities, then count trials where the parity relation holds."""
    results = []
    for _ in range(n_keys):
        key = _rb(rng, 16)
        sk = key_schedule(key)
        for n in rounds:
            states, steps = mask_sequence(expected_abs_corr, 0x01, 0x00, n)
            gl, gr = states[-1]
            c = 0 if exact_sign(signed, steps, [sk[r][0] for r in range(n)]) > 0 else 1
            hold = 0
            for _ in range(trials):
                pt = _rb(rng, 16)
                ct = feistel_encrypt_block_nrounds(pt, sk, n)
                # ct halves are post-swap: internal GL attaches to ct R, GR to ct L
                lhs = parity(pt[0], 0x01) ^ parity(ct[0], gr) ^ parity(ct[8], gl)
                hold += (lhs == c)
            results.append({"key": key.hex(), "rounds": n, "trials": trials, "holds": hold})
    return results


def b_differential(trials, rounds, rng, n_extra_keys=5):
    keys = [PUBLISHED_EXAMPLE_KEY] + [_rb(rng, 16) for _ in range(n_extra_keys)]
    S_list = [rc5_key_expansion(k) for k in keys]
    out = {}
    for n in rounds:
        tot, w1 = 0, 0
        for _ in range(trials):
            S = rng.choice(S_list)
            pt = _rb(rng, 8)
            p = bytearray(pt)
            p[0] ^= 0x80  # MSB of the L word (0x80000000, big-endian)
            c1 = rc5_core_encrypt_block_nrounds(pt, S, n)
            c2 = rc5_core_encrypt_block_nrounds(bytes(p), S, n)
            w = bin(int.from_bytes(bytes(x ^ y for x, y in zip(c1, c2)), "big")).count("1")
            tot += w
            w1 += (w == 1)
        out[n] = {"trials": trials, "mean_weight": tot / trials, "weight1_rate": w1 / trials}
    return out


def b_linear(trials, rounds, rng):
    S = rc5_key_expansion(PUBLISHED_EXAMPLE_KEY)
    out = {}
    for n in rounds:
        agree = 0
        for _ in range(trials):
            pt = _rb(rng, 8)
            ct = rc5_core_encrypt_block_nrounds(pt, S, n)
            agree += ((int.from_bytes(pt[:4], "big") ^ int.from_bytes(ct[:4], "big")) & 1) == 0
        out[n] = {"trials": trials, "corr_L": 2 * agree / trials - 1}
    return out
