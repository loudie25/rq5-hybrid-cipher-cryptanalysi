# Protocol run (full, seed 20261013, 24.6 s)

- PASS: A test vector (Stage 1) (61c966a48bf60886bb6f7e7310bc801b)
- PASS: A Feistel round-trip (200 blocks) 
- PASS: B locked chaotic key (Stage 1) 
- PASS: B RC5-core round-trip (200 blocks) 
- PASS: chaos: locked params, no cycle within budget (budget 10,000,000)
- PASS: chaos: mu=3.7 collapses to a cycle (audit method works) (3000000)
- PASS: DDT rows sum to 65536 
- PASS: DDT: only prob-1 differential is 0x80->0x80 
- PASS: LAT: only |corr|=1 nontrivial entry is 0x01->0x01 
- PASS: addition DP == brute-force DDT (n=8, 65536 pairs) (0 mismatches)
- PASS: n=32 MSB identity EDP=1; LSB differential EDP=0.5 
- PASS: A differential trail: prob exactly 1 (single-path and exact Markov), rounds 2-16 
- PASS: A differential MC: 0 mismatches at every round count (10000 trials/round)
- PASS: A byte-lane independence (2 active lanes) 
- PASS: A linear trail: predicted constant bit holds in every trial, all keys/rounds (160 key/round cases)
- PASS: B differential: 2-round signal present, saturated to random by 4 rounds (2r mean=15.2)
- PASS: B linear: no correlation beyond sampling noise (tol 0.050)
- PASS: benchmark table built 
