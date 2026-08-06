# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 8.04 | 0.02 | 0.09 | 4.97 | 13.12 (p95 18.76) |
| direct | 1024 | 1000 | 7.58 | 0.02 | 0.09 | 5.74 | 13.43 (p95 14.96) |
| direct | 16384 | 1000 | 9.47 | 0.02 | 0.09 | 22.37 | 31.96 (p95 32.19) |
| approval | 128 | 1000 | 7.41 | 0.02 | 0.08 | 4.58 | 12.09 (p95 12.29) |
| approval | 1024 | 1000 | 7.53 | 0.02 | 0.08 | 5.75 | 13.38 (p95 13.60) |
| approval | 16384 | 1000 | 8.47 | 0.02 | 0.09 | 22.18 | 30.77 (p95 32.83) |
| otp | 128 | 1000 | 7.46 | 0.02 | 0.08 | 4.60 | 12.17 (p95 12.34) |
| otp | 1024 | 1000 | 7.52 | 0.03 | 0.08 | 5.70 | 13.32 (p95 13.55) |
| otp | 16384 | 1000 | 9.07 | 0.02 | 0.10 | 22.28 | 31.47 (p95 33.85) |
| anon | 128 | 1000 | 7.50 | 1.65 | 0.10 | 4.60 | 13.85 (p95 14.10) |
| anon | 1024 | 1000 | 7.77 | 9.52 | 0.09 | 5.74 | 23.13 (p95 23.54) |
| anon | 16384 | 1000 | 9.28 | 132.31 | 0.10 | 22.31 | 164.00 (p95 169.07) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
