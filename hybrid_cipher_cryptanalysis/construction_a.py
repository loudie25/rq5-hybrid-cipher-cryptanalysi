"""
Construction A: Feistel-embedded Extended Vigenere cipher.
Copied from the Project's phase2_construction_a.py (Stage 1-locked, verified
reimplementation), with one addition for Stage 5: a round-count-parameterized
Feistel function so trail predictions can be validated at every named
round-count variant (2,4,6,8,10,12,14,16), not only the full 16-round cipher.
"""

PRIME_XOR_1 = bytes([
    0x02, 0x35, 0x03, 0x2F,
    0x05, 0x2B, 0x07, 0x29,
    0x0B, 0x25, 0x0D, 0x1F,
    0x11, 0x1D, 0x13, 0x17,
])

PRIME_XOR_2 = bytes([
    0x17, 0x59, 0x1D, 0x53,
    0x1F, 0x4F, 0x25, 0x49,
    0x29, 0x47, 0x2B, 0x43,
    0x2F, 0x3D, 0x35, 0x3B,
])

RCON_PERMUTATION = bytes([
    0x47, 0x54, 0x23, 0x2F, 0x52, 0x3B, 0x24, 0x0D,
    0x51, 0x04, 0x02, 0x34, 0x52, 0x34, 0x57, 0x42,
])

RCON_KEYSCHEDULE = bytes([
    0x0E, 0x0F, 0x5C, 0x41, 0x23, 0x59, 0x4F, 0x20,
    0x26, 0x2E, 0x1A, 0x2B, 0x26, 0x20, 0x4F, 0x32,
])

SAMPLE_PLAINTEXT_FIG1 = b"Jumpoverthemoon."
assert len(SAMPLE_PLAINTEXT_FIG1) == 16


def rotword(w: int) -> int:
    w &= 0xFFFFFFFF
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _word_expand(w0_3, rcon_bytes, n_words):
    words = list(w0_3)
    rcon_idx = 0
    while len(words) < n_words:
        i = len(words)
        if i % 4 == 0:
            rc4 = rcon_bytes[rcon_idx * 4:(rcon_idx + 1) * 4]
            rcon_idx += 1
            rcon_word = int.from_bytes(rc4, "big")
            w = words[i - 4] ^ (rotword(words[i - 1]) ^ rcon_word)
        else:
            w = words[i - 4] ^ words[i - 1]
        words.append(w & 0xFFFFFFFF)
    return words


def _pht_mod256(matrix):
    def pht_vec(v):
        a, b, c, d = v
        ap = (a + b + c + d) % 256
        bp = (a + 2 * b + c + 2 * d) % 256
        cp = (a + b + 2 * c + 2 * d) % 256
        dp = (a + 2 * b + c + 4 * d) % 256
        return [ap, bp, cp, dp]

    rows = [pht_vec(row) for row in matrix]
    cols = list(zip(*rows))
    cols = [pht_vec(list(col)) for col in cols]
    return [list(row) for row in zip(*cols)]


def _xor_matrix(m, x):
    return [[m[r][c] ^ x[r * 4 + c] for c in range(4)] for r in range(4)]


def _shiftrows(m):
    return [m[r][r:] + m[r][:r] for r in range(4)]


def _mixrows(m):
    rows = [row[:] for row in m]
    for i in range(4):
        nxt = rows[(i + 1) % 4]
        rows[i] = [rows[i][k] ^ nxt[k] for k in range(4)]
    return rows


def initial_permutation(plaintext_block: bytes) -> bytes:
    assert len(plaintext_block) == 16
    m = [[0] * 4 for _ in range(4)]
    idx = 0
    for c in range(4):
        for r in range(4):
            m[r][c] = plaintext_block[idx]
            idx += 1

    m = _pht_mod256(m)
    m = _xor_matrix(m, PRIME_XOR_1)

    w0_3 = [int.from_bytes(bytes(row), "big") for row in m]
    words = _word_expand(w0_3, RCON_PERMUTATION, n_words=20)
    last4 = words[16:20]
    rows16_19 = [list(w.to_bytes(4, "big")) for w in last4]
    rows16_19 = _shiftrows(rows16_19)
    rows16_19 = _mixrows(rows16_19)
    rows16_19 = _xor_matrix(rows16_19, PRIME_XOR_2)

    out = bytearray(16)
    idx = 0
    for c in range(4):
        for r in range(4):
            out[idx] = rows16_19[r][c] & 0xFF
            idx += 1
    return bytes(out)


def key_schedule(key128: bytes):
    assert len(key128) == 16
    w0_3 = [int.from_bytes(key128[4 * i:4 * i + 4], "big") for i in range(4)]
    words = _word_expand(w0_3, RCON_KEYSCHEDULE, n_words=68)
    subkeys = []
    for j in range(16):
        k03 = (words[4 * j + 4] ^ words[4 * j + 6]) & 0xFFFFFFFF
        k47 = (words[4 * j + 5] ^ words[4 * j + 7]) & 0xFFFFFFFF
        subkeys.append(k03.to_bytes(4, "big") + k47.to_bytes(4, "big"))
    return subkeys


def extended_vigenere(data8: bytes, subkey8: bytes) -> bytes:
    return bytes((d + s) % 256 for d, s in zip(data8, subkey8))


def feistel_encrypt_block(permuted_block: bytes, subkeys) -> bytes:
    """Original, full 16-round cipher (unchanged from the verified
    reimplementation)."""
    assert len(permuted_block) == 16
    L, R = bytearray(permuted_block[:8]), bytearray(permuted_block[8:])
    for r in range(16):
        temp = bytes(R)
        encrypted_R = extended_vigenere(bytes(R), subkeys[r])
        R = bytearray(a ^ b for a, b in zip(L, encrypted_R))
        L = bytearray(temp)
    L, R = R, L
    return bytes(L) + bytes(R)


def feistel_encrypt_block_nrounds(permuted_block: bytes, subkeys, n_rounds: int) -> bytes:
    """Stage 5 addition: same Feistel structure, run for exactly n_rounds
    rounds (using subkeys[0:n_rounds]), with the same final-swap convention
    as the full cipher, so round-count variants (2,4,...,16) can be tested
    directly against trail predictions without altering the verified
    16-round function above."""
    assert len(permuted_block) == 16
    assert 1 <= n_rounds <= len(subkeys)
    L, R = bytearray(permuted_block[:8]), bytearray(permuted_block[8:])
    for r in range(n_rounds):
        temp = bytes(R)
        encrypted_R = extended_vigenere(bytes(R), subkeys[r])
        R = bytearray(a ^ b for a, b in zip(L, encrypted_R))
        L = bytearray(temp)
    L, R = R, L
    return bytes(L) + bytes(R)


def feistel_decrypt_block(ciphertext_block: bytes, subkeys) -> bytes:
    assert len(ciphertext_block) == 16
    L, R = bytearray(ciphertext_block[:8]), bytearray(ciphertext_block[8:])
    L, R = R, L
    for r in reversed(range(16)):
        R_old = bytes(L)
        encrypted_R = extended_vigenere(R_old, subkeys[r])
        L_old = bytearray(a ^ b for a, b in zip(R, encrypted_R))
        L, R = L_old, bytearray(R_old)
    return bytes(L) + bytes(R)


def full_encrypt(plaintext_block: bytes, key128: bytes) -> bytes:
    """Complete pipeline: initial permutation (keyless) -> Feistel (keyed)."""
    permuted = initial_permutation(plaintext_block)
    subkeys = key_schedule(key128)
    return feistel_encrypt_block(permuted, subkeys)
