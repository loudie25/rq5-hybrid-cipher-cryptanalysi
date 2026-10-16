"""Stage 6: literature benchmarks and comparative table (log2 units).
Figures were retrieved from web-extracted text; confirm against primary papers."""
import math

LITERATURE = [
    # name, model, log2 data, key bits, source
    ("DES-16", "differential", 47, 56, "Biham & Shamir 1991"),
    ("DES-16", "linear", 43, 56, "Matsui 1993/1994"),
    ("RC5-32/12", "differential", 44, 128, "Biryukov & Kushilevitz 1998"),
    ("RC5-32 6 rounds", "linear (claimed, later disputed)", 57, 128, "Kaliski & Yin 1995; gaps per Selcuk"),
]


def comparison_table(b_weight1_rate_2rounds):
    rows = [dict(cipher=n, model=m, log2_data=d, log2_exhaustive=k, source=s,
                 bits_attack_beats_exhaustive=k - d) for n, m, d, k, s in LITERATURE]
    for model in ("differential", "linear"):
        rows.append(dict(cipher="Construction A (all rounds 2-16)", model=model, log2_data=0,
                         log2_exhaustive=128, source="Stage 5", bits_attack_beats_exhaustive=128))
    if b_weight1_rate_2rounds and b_weight1_rate_2rounds > 0:
        lg = round(math.log2(1 / b_weight1_rate_2rounds), 1)
        rows.append(dict(cipher="Construction B (2 rounds)", model="differential", log2_data=lg,
                         log2_exhaustive=128, source="Stage 5",
                         bits_attack_beats_exhaustive=round(128 - lg, 1)))
    return rows
