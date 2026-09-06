# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 16384 | 1000 | 8.49 | 134.44 | 0.10 | 23.29 | 166.32 (p95 177.72) |
| approval | 16384 | 1000 | 7.83 | 0.02 | 0.08 | 28.89 | 36.83 (p95 33.70) |
| otp | 1024 | 1000 | 7.49 | 0.02 | 0.09 | 5.73 | 13.32 (p95 13.66) |
| approval | 128 | 1000 | 7.39 | 0.02 | 0.08 | 4.57 | 12.06 (p95 12.27) |
| direct | 128 | 1000 | 7.53 | 0.02 | 0.09 | 4.62 | 12.26 (p95 12.66) |
| anon | 1024 | 1000 | 7.80 | 9.68 | 0.10 | 5.85 | 23.43 (p95 26.54) |
| approval | 1024 | 1000 | 7.54 | 0.02 | 0.08 | 5.72 | 13.36 (p95 13.60) |
| otp | 16384 | 1000 | 7.81 | 0.02 | 0.08 | 22.80 | 30.72 (p95 32.90) |
| direct | 16384 | 1000 | 7.86 | 0.02 | 0.09 | 29.00 | 36.97 (p95 33.39) |
| direct | 1024 | 1000 | 7.63 | 0.02 | 0.08 | 5.72 | 13.46 (p95 13.75) |
| otp | 128 | 1000 | 7.53 | 0.02 | 0.08 | 4.62 | 12.24 (p95 12.55) |
| anon | 128 | 1000 | 7.60 | 1.71 | 0.09 | 4.61 | 14.00 (p95 14.29) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
