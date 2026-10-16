// Independent runtime leg for RQ5 (replaces the unexecuted MATLAB leg).
// Same recurrence, same evaluation order as construction_b.logistic_sequence:
//   x_{n+1} = (mu * x * (1 - x) + eps * n) mod 1,  200 pre-iterations, counter n advances every step.
// Output: 1e6 values, each as the 16-hex-digit IEEE-754 binary64 bit pattern (big-endian), one per line.
const fs = require('fs');
const MU = 3.99, X0 = 0.5, EPS = 1e-6, PRE = 200, N_OUT = parseInt(process.argv[2] || '1000000', 10);
const out_path = process.argv[3] || 'results/rq5_env3_node_1e6.txt';
const buf = new DataView(new ArrayBuffer(8));
let x = X0, n = 0;
for (let i = 0; i < PRE; i++) { x = (MU * x * (1 - x) + EPS * n) % 1; n++; }
const lines = new Array(N_OUT);
for (let i = 0; i < N_OUT; i++) {
  x = (MU * x * (1 - x) + EPS * n) % 1;
  n++;
  buf.setFloat64(0, x, false);
  lines[i] = buf.getBigUint64(0, false).toString(16).padStart(16, '0');
}
fs.writeFileSync(out_path, lines.join('\n') + '\n');
console.log('wrote', N_OUT, 'values to', out_path, 'runtime', process.version, process.arch);
