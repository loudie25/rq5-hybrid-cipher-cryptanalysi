# Hybrid Cipher Cryptanalysis Protocol (Stages 2-6 consolidated)

Reusable, runnable protocol for the study of two hybrid ciphers: Construction A
(Feistel + Extended Vigenere byte-wise addition) and Construction B
(Logistic-map-assisted RC5-32/12).

## Run
    pip install -r requirements.txt
    python3 run_all.py --quick   # ~3 s: 1,000 MC trials, 200k-iteration chaos audit
    python3 run_all.py --full    # ~25 s: 10,000 MC trials (Stage 5 spec), 10M-iteration chaos audit
Exit code is non-zero if any asserted check fails. Output: results/protocol_report.{json,md}.

## Modules (one per stage)
| Stage | Module | Role |
| --- | --- | --- |
| 2 | construction_a.py, construction_b.py | Verified reimplementations, round-parameterized, instrumented |
| 3 | chaos_audit.py | Brent cycle detection on the logistic map (4 parameter cases) |
| 4 | ddt_lat.py | 256x256 DDT/LAT, validated n-bit addition differential DP |
| 5 | trails.py, monte_carlo.py | Exact Markov trail chaining; Monte Carlo against the real ciphers |
| 6 | benchmark.py | Literature benchmark table and margin computation |
| 7 | run_all.py | Driver with assertions and report writer |

## Method (what the protocol does, in order)
1. Verify each reimplementation against its test vector and by round-trip.
2. Audit the chaos generator for cycles; compare against a deliberately weak parameter set to show the audit can fail.
3. Build exact primitive tables; cross-check any analytical shortcut against brute force (0 mismatches required).
4. Chain characteristics (exactly where the state space allows, by simulation otherwise).
5. Validate every trail against the real cipher; a single mismatch fails the run. Remember the cipher's final L,R swap when mapping internal states to ciphertext.
6. Compare margins with literature figures, stating sign convention and caveats.

## Scope and caveats (read before citing results)
- Construction A results cover the core Feistel transformation. The keyless, non-invertible initial permutation is NOT composed into the trails.
- Construction B results are single-trail simulations: a lower bound on weakness, not evidence of security at 12 rounds (literature: 2^44 chosen plaintexts). Whether the chaotic wrapper blocks that attack is open.
- Literature figures in benchmark.py came from web-extracted text and one secondhand citation (Kaliski-Yin, disputed). Confirm against primary papers.
- Cross-environment reproducibility (RQ5) is NOT yet run: octave/logistic_reference.m is unexecuted. Run chaos_reference_dump.py, run the Octave script elsewhere, then diff the two files in results/.

## Stage 8 (Construction B vs the published RC5 differential attack)
Scripts (run from this directory; each writes results/stage8_*.json):
- `stage8_trail_dp.py`  trail DP over (dL,dR) for the XOR-keyed core (S8_K sets the beam width; 500 is too narrow, 4000 takes ~30 s, 40000 takes ~6 min)
- `stage8_mc_validate.py`  DP vs real core, key-averaged Monte Carlo, rounds 1-5
- `stage8_heldout.py`  discovery on one key, evaluation on eight others (removes selection bias)
- `stage8_perkey.py`  per-key heavy-hitter (maximum) differential probability, rounds 2-5
- `stage8_wrapper.py`  wrapper model (block-index byte permutation + XOR mask) around the real core
Caveats: the DP assumes independent uniform rotation amounts (Markov-cipher assumption), treats a changed
rotation amount as a lost pair (so it is a lower bound on attacker success only up to that assumption), and is
validated by simulation only to 5 rounds; 6 to 12 rounds are extrapolated by the DP alone.
