# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.79 | 0.02 | 0.08 | 4.83 | 12.72 (p95 18.59) |
| direct | 1024 | 1000 | 7.55 | 0.02 | 0.08 | 5.71 | 13.36 (p95 15.45) |
| direct | 16384 | 1000 | 7.64 | 0.02 | 0.08 | 28.45 | 36.20 (p95 31.03) |
| approval | 128 | 1000 | 7.12 | 0.02 | 0.08 | 4.40 | 11.62 (p95 11.95) |
| approval | 1024 | 1000 | 7.15 | 0.02 | 0.08 | 5.43 | 12.68 (p95 12.99) |
| approval | 16384 | 1000 | 7.74 | 0.02 | 0.08 | 28.17 | 36.02 (p95 33.65) |
| otp | 128 | 1000 | 7.10 | 0.02 | 0.07 | 4.36 | 11.55 (p95 11.82) |
| otp | 1024 | 1000 | 7.16 | 0.02 | 0.08 | 5.46 | 12.71 (p95 12.97) |
| otp | 16384 | 1000 | 7.41 | 0.02 | 0.08 | 22.11 | 29.62 (p95 30.82) |
| anon | 128 | 1000 | 7.27 | 1.63 | 0.08 | 4.42 | 13.40 (p95 13.89) |
| anon | 1024 | 1000 | 7.31 | 8.98 | 0.09 | 5.47 | 21.85 (p95 23.18) |
| anon | 16384 | 1000 | 8.11 | 130.52 | 0.09 | 22.37 | 161.10 (p95 214.67) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
