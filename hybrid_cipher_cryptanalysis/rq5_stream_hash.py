"""Emit SHA-256 of the 10^6-value locked Logistic stream as 16-hex IEEE-754 words (one per line).
Used by the cross-platform CI leg. Run from the package root. Usage: python rq5_stream_hash.py [out.txt]"""
import hashlib, struct, sys
from construction_b import logistic_sequence
out = sys.argv[1] if len(sys.argv) > 1 else "rq5_stream.txt"
lines = [format(struct.unpack(">Q", struct.pack(">d", x))[0], "016x") for x in logistic_sequence(1_000_000)]
data = "\n".join(lines) + "\n"
open(out, "w").write(data)
print(hashlib.sha256(data.encode()).hexdigest(), out)
