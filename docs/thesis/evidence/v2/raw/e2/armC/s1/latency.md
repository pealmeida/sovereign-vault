# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.51 | 0.02 | 0.08 | 4.66 | 12.27 (p95 12.66) |
| approval | 1024 | 1000 | 7.51 | 0.04 | 0.07 | 5.74 | 13.36 (p95 14.23) |
| approval | 128 | 1000 | 7.45 | 0.02 | 0.07 | 4.63 | 12.17 (p95 12.32) |
| anon | 1024 | 1000 | 7.69 | 9.48 | 0.08 | 5.72 | 22.97 (p95 24.09) |
| anon | 16384 | 1000 | 10.38 | 131.79 | 0.10 | 22.85 | 165.11 (p95 171.61) |
| direct | 16384 | 1000 | 8.78 | 0.02 | 0.10 | 22.56 | 31.46 (p95 36.01) |
| anon | 128 | 1000 | 7.64 | 1.72 | 0.08 | 4.65 | 14.09 (p95 15.11) |
| otp | 128 | 1000 | 7.48 | 0.02 | 0.07 | 4.61 | 12.18 (p95 12.48) |
| otp | 1024 | 1000 | 7.52 | 0.02 | 0.08 | 5.72 | 13.33 (p95 13.56) |
| direct | 1024 | 1000 | 7.54 | 0.02 | 0.07 | 5.65 | 13.29 (p95 13.51) |
| otp | 16384 | 1000 | 8.83 | 0.02 | 0.07 | 22.18 | 31.10 (p95 31.92) |
| approval | 16384 | 1000 | 8.39 | 0.02 | 0.07 | 22.32 | 30.81 (p95 32.17) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
