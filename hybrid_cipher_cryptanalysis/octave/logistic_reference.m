% Cross-environment leg (Stage 3 / RQ5). NOT YET EXECUTED: no Octave/MATLAB was
% available when this protocol was assembled. Run in GNU Octave or MATLAB, then
%   diff results/chaos_reference_python.txt results/chaos_reference_octave.txt
mu = 3.99; x = 0.5; eps_ = 1e-6; n = 0;
for i = 1:200
  x = mod(mu * x * (1 - x) + eps_ * n, 1.0); n = n + 1;
end
fid = fopen('results/chaos_reference_octave.txt', 'w');
for i = 1:1000
  x = mod(mu * x * (1 - x) + eps_ * n, 1.0); n = n + 1;
  bytes = typecast(swapbytes(x), 'uint8');   % big-endian double
  fprintf(fid, '%02x', bytes); fprintf(fid, '\n');
end
fclose(fid);
