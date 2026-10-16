#!/usr/bin/env python3
"""Single entry point for the consolidated cryptanalysis protocol (Stages 2-6).

  python3 run_all.py --quick   # ~minutes: 1,000 MC trials, 200k-iteration chaos audit
  python3 run_all.py --full    # 10,000 MC trials (Stage 5 spec), 10M-iteration chaos audit

Every headline result is ASSERTED (not just printed); the run exits non-zero if
any check fails. Writes results/protocol_report.json and results/protocol_report.md."""
import argparse, json, math, random, sys, time
import numpy as np

import construction_a as A
import construction_b as B
from ddt_lat import build_ddt, build_lat, edp_add, validate_dp_against_ddt
from trails import single_path_diff, exact_markov_diff, mask_sequence, exact_sign
import monte_carlo as MC
import chaos_audit
from benchmark import comparison_table

ap = argparse.ArgumentParser()
g = ap.add_mutually_exclusive_group()
g.add_argument("--quick", action="store_true")
g.add_argument("--full", action="store_true")
ap.add_argument("--seed", type=int, default=20261013)
args = ap.parse_args()
FULL = args.full
TRIALS = 10000 if FULL else 1000
CHAOS_BUDGET = 10_000_000 if FULL else 200_000
rng = random.Random(args.seed)
A_ROUNDS = [2, 4, 6, 8, 10, 12, 14, 16]
B_ROUNDS = [2, 4, 6, 8, 10, 12]

report, checks = {"mode": "full" if FULL else "quick", "seed": args.seed, "trials": TRIALS}, []


def check(name, ok, detail=""):
    checks.append({"check": name, "pass": bool(ok), "detail": detail})
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)


t0 = time.time()
# ---- Stage 2: reimplementation -------------------------------------------
key_a = bytes(range(16))
ct_a = A.full_encrypt(A.SAMPLE_PLAINTEXT_FIG1, key_a).hex()
check("A test vector (Stage 1)", ct_a == "61c966a48bf60886bb6f7e7310bc801b", ct_a)
sk = A.key_schedule(key_a)
rt = all(A.feistel_decrypt_block(A.feistel_encrypt_block(b, sk), sk) == b
         for b in (bytes(rng.randrange(256) for _ in range(16)) for _ in range(200)))
check("A Feistel round-trip (200 blocks)", rt)
check("B locked chaotic key (Stage 1)", B.derive_chaotic_key().hex() == "0209247dfe020a2887fd061756e360ef")
S = B.rc5_key_expansion(B.PUBLISHED_EXAMPLE_KEY)
ok = True
for _ in range(200):
    L, R = rng.getrandbits(32), rng.getrandbits(32)
    l, r = B.initial_whitening(L, R, S)
    l, r = B.round_function_forward(l, r, S)
    l, r = B.round_function_inverse(l, r, S)
    ok &= B.inverse_initial_whitening(l, r, S) == (L, R)
check("B RC5-core round-trip (200 blocks)", ok)

# ---- Stage 3: chaos audit --------------------------------------------------
aud = chaos_audit.run_audit(CHAOS_BUDGET)
report["chaos_audit"] = aud
check("chaos: locked params, no cycle within budget", not aud[0]["cycle_detected"], f"budget {CHAOS_BUDGET:,}")
if FULL:
    check("chaos: mu=3.7 collapses to a cycle (audit method works)", aud[3]["cycle_detected"], str(aud[3]["cycle_length"]))

# ---- Stage 4: DDT / LAT / addition DP --------------------------------------
ddt = build_ddt()
ddt_prob = ddt / 65536.0
check("DDT rows sum to 65536", all(int(ddt[i].sum()) == 65536 for i in range(256)))
nz = ddt[1:]
check("DDT: only prob-1 differential is 0x80->0x80",
      ddt[0x80][0x80] == 65536 and (nz == 65536).sum() == 1)
exp_abs, signed = build_lat()
check("LAT: only |corr|=1 nontrivial entry is 0x01->0x01",
      abs(exp_abs[1][1] - 1) < 1e-12 and (np.isclose(exp_abs[1:, 1:], 1)).sum() == 1)
bad = validate_dp_against_ddt(ddt)
check("addition DP == brute-force DDT (n=8, 65536 pairs)", bad == 0, f"{bad} mismatches")
check("n=32 MSB identity EDP=1; LSB differential EDP=0.5",
      abs(edp_add(1 << 31, 1 << 31, 32) - 1) < 1e-12 and abs(edp_add(1, 1, 32) - 0.5) < 1e-12)

# ---- Stage 5: trails + Monte Carlo ----------------------------------------
internal = {}
for n in A_ROUNDS:
    states, p = single_path_diff(ddt_prob, 0, 0x80, n)
    P = exact_markov_diff(ddt_prob, 0, 0x80, n)
    internal[n] = states[-1]
    assert abs(p - 1) < 1e-12 and abs(P[states[-1]] - 1) < 1e-12
check("A differential trail: prob exactly 1 (single-path and exact Markov), rounds 2-16", True)

mc_d = MC.a_differential(TRIALS, A_ROUNDS, rng, internal)
check("A differential MC: 0 mismatches at every round count",
      all(v["mismatches"] == 0 for v in mc_d.values()), f"{TRIALS} trials/round")
mc_i = MC.a_lane_independence(TRIALS, rng, internal)
check("A byte-lane independence (2 active lanes)", mc_i["mismatches"] == 0)
mc_l = MC.a_linear_multikey(20 if FULL else 5, 2000 if FULL else 300, A_ROUNDS, rng, exp_abs, signed)
check("A linear trail: predicted constant bit holds in every trial, all keys/rounds",
      all(r["holds"] == r["trials"] for r in mc_l), f"{len(mc_l)} key/round cases")
mc_bd = MC.b_differential(TRIALS, B_ROUNDS, rng)
check("B differential: 2-round signal present, saturated to random by 4 rounds",
      mc_bd[2]["mean_weight"] < 20 and all(abs(mc_bd[n]["mean_weight"] - 32) < 1.5 for n in (4, 6, 8, 10, 12)),
      f"2r mean={mc_bd[2]['mean_weight']:.1f}")
mc_bl = MC.b_linear(TRIALS, [1, 2, 4, 8, 12], rng)
tol = 5 / math.sqrt(TRIALS)
check("B linear: no correlation beyond sampling noise", all(abs(v["corr_L"]) < tol for v in mc_bl.values()),
      f"tol {tol:.3f}")

# ---- Stage 6: benchmark -----------------------------------------------------
table = comparison_table(mc_bd[2]["weight1_rate"])
check("benchmark table built", len(table) >= 7)

report.update(dict(ddt_max=[0x80, 0x80, 1.0], mc_a_differential=mc_d, mc_a_independence=mc_i,
                   mc_a_linear_cases=len(mc_l), mc_b_differential=mc_bd, mc_b_linear=mc_bl,
                   benchmark=table, checks=checks, seconds=round(time.time() - t0, 1)))
import os
os.makedirs("results", exist_ok=True)
json.dump(report, open("results/protocol_report.json", "w"), indent=2, default=str)
with open("results/protocol_report.md", "w") as f:
    f.write(f"# Protocol run ({report['mode']}, seed {args.seed}, {report['seconds']} s)\n\n")
    for c in checks:
        f.write(f"- {'PASS' if c['pass'] else 'FAIL'}: {c['check']} {('(' + c['detail'] + ')') if c['detail'] else ''}\n")
failed = [c for c in checks if not c["pass"]]
print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed in {report['seconds']} s")
sys.exit(1 if failed else 0)
