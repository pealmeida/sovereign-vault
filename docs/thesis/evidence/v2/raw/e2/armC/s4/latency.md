# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| otp | 16384 | 1000 | 9.74 | 0.03 | 0.09 | 28.89 | 38.75 (p95 44.15) |
| anon | 16384 | 1000 | 9.64 | 129.05 | 0.10 | 21.85 | 160.65 (p95 173.96) |
| approval | 16384 | 1000 | 8.61 | 0.03 | 0.08 | 21.69 | 30.42 (p95 33.59) |
| approval | 128 | 1000 | 7.65 | 0.02 | 0.08 | 4.48 | 12.23 (p95 13.55) |
| direct | 1024 | 1000 | 7.61 | 0.03 | 0.07 | 5.46 | 13.17 (p95 13.53) |
| otp | 1024 | 1000 | 7.70 | 0.03 | 0.08 | 5.54 | 13.35 (p95 13.85) |
| anon | 128 | 1000 | 8.00 | 1.72 | 0.09 | 4.67 | 14.48 (p95 20.77) |
| approval | 1024 | 1000 | 7.90 | 0.03 | 0.08 | 5.67 | 13.68 (p95 15.53) |
| direct | 16384 | 1000 | 8.61 | 0.03 | 0.08 | 21.57 | 30.30 (p95 32.04) |
| anon | 1024 | 1000 | 7.67 | 8.97 | 0.09 | 5.54 | 22.27 (p95 23.76) |
| otp | 128 | 1000 | 7.52 | 0.02 | 0.08 | 4.42 | 12.04 (p95 12.36) |
| direct | 128 | 1000 | 7.56 | 0.02 | 0.08 | 4.47 | 12.13 (p95 12.34) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
