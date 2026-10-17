"""Redraw the Construction B linear-correlation figure (paper Fig. 1) from the committed Stage 5 results.
Run from the package root: python make_fig_linear_corr.py [out.png]"""
import json, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

src = "results/stage5_construction_b_linear_results.json"
out = sys.argv[1] if len(sys.argv) > 1 else "figs/fig_linear_corr.png"
d = json.load(open(src))
res = d["results_by_round_count"]
rounds = sorted(int(r) for r in res)
corr = [res[str(r)]["corr_L_out"] for r in rounds]
se = 1 / d["trials_per_round_count"] ** 0.5

fig, ax = plt.subplots(figsize=(6.2, 3.6), dpi=300)
ax.axhspan(-3 * se, 3 * se, color="0.9", zorder=0, label="±3 standard errors (±0.03)")
ax.axhline(0, color="0.4", lw=0.8)
ax.plot(rounds, corr, "o-", color="#1f4e79", ms=5, lw=1.4, label="Measured correlation")
ax.set_xlabel("Rounds")
ax.set_ylabel("Correlation of LSB identity")
ax.set_xticks(rounds)
ax.set_ylim(-0.06, 0.06)
ax.legend(frameon=False, fontsize=8, loc="upper right")
ax.set_title("Construction B: linear correlation by round count", fontsize=10)
fig.tight_layout()
fig.savefig(out)
print("wrote", out)
