# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| approval | 16384 | 1000 | 8.05 | 0.03 | 0.07 | 29.17 | 37.32 (p95 33.10) |
| direct | 16384 | 1000 | 7.68 | 0.03 | 0.14 | 28.26 | 36.12 (p95 32.82) |
| otp | 1024 | 1000 | 7.47 | 0.02 | 0.07 | 5.59 | 13.15 (p95 13.26) |
| otp | 16384 | 1000 | 7.54 | 0.02 | 0.07 | 22.53 | 30.17 (p95 31.90) |
| anon | 16384 | 1000 | 7.99 | 130.90 | 0.09 | 22.59 | 161.57 (p95 171.50) |
| approval | 1024 | 1000 | 7.34 | 0.03 | 0.07 | 5.67 | 13.11 (p95 13.23) |
| otp | 128 | 1000 | 7.28 | 0.02 | 0.07 | 4.47 | 11.85 (p95 12.02) |
| direct | 128 | 1000 | 7.30 | 0.03 | 0.07 | 4.50 | 11.90 (p95 12.02) |
| anon | 1024 | 1000 | 7.52 | 9.24 | 0.07 | 5.59 | 22.42 (p95 22.95) |
| direct | 1024 | 1000 | 7.89 | 0.03 | 0.08 | 5.89 | 13.89 (p95 18.39) |
| approval | 128 | 1000 | 7.39 | 0.02 | 0.07 | 4.57 | 12.05 (p95 12.85) |
| anon | 128 | 1000 | 7.24 | 1.66 | 0.08 | 4.48 | 13.46 (p95 13.66) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
