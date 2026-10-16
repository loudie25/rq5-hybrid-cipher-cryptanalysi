"""
Construction B: Logistic-map-assisted RC5 hybrid cipher.
Copied from the Project's phase2_construction_b.py (Stage 1-locked,
verified reimplementation), with one addition for Stage 5: a round-count-
parameterized round function so trail predictions can be tested at every
named round-count variant (2,4,6,8,10,12), not only the full 12-round core.
"""

import math

W = 32
R_ROUNDS = 12
B_KEY = 16
MASK = 0xFFFFFFFF
P32 = 0xB7E15163
Q32 = 0x9E3779B9

PUBLISHED_EXAMPLE_KEY = bytes.fromhex("E169FD0A29878786870A4B01C3D2E7F8")


def rotl32(x, s):
    s &= 31
    x &= MASK
    return ((x << s) | (x >> (32 - s))) & MASK


def rotr32(x, s):
    s &= 31
    x &= MASK
    return ((x >> s) | (x << (32 - s))) & MASK


def rc5_key_expansion(key: bytes, w=W, r=R_ROUNDS):
    assert len(key) == B_KEY
    t = 2 * (r + 1)
    u = w // 8
    c = max(1, math.ceil(len(key) / u))
    L = [0] * c
    for i in range(len(key) - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) + key[i]) & MASK

    S = [0] * t
    S[0] = P32
    for i in range(1, t):
        S[i] = (S[i - 1] + Q32) & MASK

    i = j = 0
    A = B = 0
    for _ in range(3 * max(t, c)):
        A = S[i] = rotl32((S[i] + A + B) & MASK, 3)
        B = L[j] = rotl32((L[j] + A + B) & MASK, (A + B) & MASK)
        i = (i + 1) % t
        j = (j + 1) % c
    return S


CONST_CORRECTION_L = 0x00000001
CONST_CORRECTION_R = 0x00000002


def initial_whitening(L, R, S):
    L2 = ((L ^ S[0]) + CONST_CORRECTION_L) & MASK
    R2 = ((R ^ S[1]) + CONST_CORRECTION_R) & MASK
    return L2, R2


def inverse_initial_whitening(L2, R2, S):
    L = ((L2 - CONST_CORRECTION_L) & MASK) ^ S[0]
    R = ((R2 - CONST_CORRECTION_R) & MASK) ^ S[1]
    return L, R


def round_function_forward(L, R, S):
    """Original, full R_ROUNDS-round transform (unchanged)."""
    for i in range(1, R_ROUNDS + 1):
        L = (rotl32(L ^ R, R % 32) ^ S[2 * i]) & MASK
        R = (rotl32(R ^ L, L % 32) ^ S[2 * i + 1]) & MASK
    return L, R


def round_function_forward_nrounds(L, R, S, n_rounds):
    """Stage 5 addition: same per-round transform, run for exactly
    n_rounds rounds (1..R_ROUNDS), using S[2..2*n_rounds+1], so round-count
    variants can be tested directly without altering the verified
    R_ROUNDS-round function above."""
    assert 1 <= n_rounds <= R_ROUNDS
    for i in range(1, n_rounds + 1):
        L = (rotl32(L ^ R, R % 32) ^ S[2 * i]) & MASK
        R = (rotl32(R ^ L, L % 32) ^ S[2 * i + 1]) & MASK
    return L, R


def round_function_inverse(L, R, S):
    for i in range(R_ROUNDS, 0, -1):
        R = rotr32(R ^ S[2 * i + 1], L % 32) ^ L
        L = rotr32(L ^ S[2 * i], R % 32) ^ R
    return L, R & MASK


def rc5_core_encrypt_block(pt8: bytes, S) -> bytes:
    assert len(pt8) == 8
    L = int.from_bytes(pt8[0:4], "big")
    R = int.from_bytes(pt8[4:8], "big")
    L, R = initial_whitening(L, R, S)
    L, R = round_function_forward(L, R, S)
    L = (L ^ S[2 * R_ROUNDS]) & MASK
    R = (R ^ S[2 * R_ROUNDS + 1]) & MASK
    return L.to_bytes(4, "big") + R.to_bytes(4, "big")


def rc5_core_encrypt_block_nrounds(pt8: bytes, S, n_rounds: int) -> bytes:
    """Stage 5: whitening -> n_rounds of the per-round transform -> output
    whitening keyed off the LAST round actually executed (so the output
    difference reflects exactly n_rounds of mixing, consistent with how
    round-count variants are defined for the full cipher)."""
    assert len(pt8) == 8
    L = int.from_bytes(pt8[0:4], "big")
    R = int.from_bytes(pt8[4:8], "big")
    L, R = initial_whitening(L, R, S)
    L, R = round_function_forward_nrounds(L, R, S, n_rounds)
    L = (L ^ S[2 * n_rounds]) & MASK
    R = (R ^ S[2 * n_rounds + 1]) & MASK
    return L.to_bytes(4, "big") + R.to_bytes(4, "big")


# ---------------------------------------------------------------------------
# Stage 1 LOCKED chaos parameters and generator (formally adopted substitutes;
# the source paper never publishes mu, x0, epsilon or the perturbation form).
# ---------------------------------------------------------------------------
LOCKED_MU = 3.99
LOCKED_X0 = 0.5
LOCKED_EPSILON = 1e-6
LOCKED_PRE_ITERATIONS = 200


def logistic_sequence(n_values, mu=LOCKED_MU, x0=LOCKED_X0,
                      epsilon=LOCKED_EPSILON, pre_iterations=LOCKED_PRE_ITERATIONS):
    """x_{n+1} = mu * x_n * (1 - x_n) + epsilon * n  (mod 1.0)"""
    x, n = x0, 0
    for _ in range(pre_iterations):
        x = (mu * x * (1 - x) + epsilon * n) % 1.0
        n += 1
    out = []
    for _ in range(n_values):
        x = (mu * x * (1 - x) + epsilon * n) % 1.0
        out.append(x)
        n += 1
    return out


def derive_chaotic_key(mu=LOCKED_MU, x0=LOCKED_X0, epsilon=LOCKED_EPSILON,
                       pre_iterations=LOCKED_PRE_ITERATIONS, key_bytes=16):
    """Direct byte-packing of floor(x*255) mod 256 (this study's own
    convention; the paper does not specify the chaos-to-key mixing)."""
    seq = logistic_sequence(key_bytes, mu, x0, epsilon, pre_iterations)
    return bytes(math.floor(x * 255) % 256 for x in seq)
