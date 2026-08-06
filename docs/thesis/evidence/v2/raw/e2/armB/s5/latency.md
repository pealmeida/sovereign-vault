# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.81 | 0.02 | 0.08 | 4.82 | 12.73 (p95 16.62) |
| direct | 1024 | 1000 | 7.48 | 0.02 | 0.09 | 5.63 | 13.21 (p95 13.88) |
| direct | 16384 | 1000 | 7.87 | 0.02 | 0.08 | 28.62 | 36.58 (p95 32.04) |
| approval | 128 | 1000 | 7.34 | 0.02 | 0.07 | 4.51 | 11.94 (p95 12.23) |
| approval | 1024 | 1000 | 7.35 | 0.02 | 0.07 | 5.60 | 13.04 (p95 13.26) |
| approval | 16384 | 1000 | 7.73 | 0.04 | 0.08 | 28.15 | 36.00 (p95 33.50) |
| otp | 128 | 1000 | 7.32 | 0.02 | 0.07 | 4.48 | 11.89 (p95 12.09) |
| otp | 1024 | 1000 | 7.62 | 0.02 | 0.07 | 5.75 | 13.47 (p95 16.60) |
| otp | 16384 | 1000 | 7.70 | 0.02 | 0.08 | 22.57 | 30.37 (p95 33.06) |
| anon | 128 | 1000 | 7.45 | 1.63 | 0.07 | 4.44 | 13.59 (p95 13.69) |
| anon | 1024 | 1000 | 7.59 | 9.32 | 0.08 | 5.65 | 22.63 (p95 24.15) |
| anon | 16384 | 1000 | 8.19 | 133.12 | 0.10 | 22.69 | 164.11 (p95 212.00) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
