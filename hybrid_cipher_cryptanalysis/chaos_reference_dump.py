"""Writes the first 1000 post-transient logistic-map values (locked params) as
IEEE-754 hex, for bit-for-bit comparison against octave/logistic_reference.m
(the cross-environment reproducibility leg of RQ5; Stage 3)."""
import struct
from construction_b import logistic_sequence
with open("results/chaos_reference_python.txt", "w") as f:
    for x in logistic_sequence(1000):
        f.write(struct.pack(">d", x).hex() + "\n")
print("wrote results/chaos_reference_python.txt")
