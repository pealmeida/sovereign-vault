# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 128 | 1000 | 7.48 | 1.71 | 0.09 | 4.57 | 13.85 (p95 14.65) |
| direct | 16384 | 1000 | 7.85 | 0.03 | 0.09 | 29.12 | 37.08 (p95 31.98) |
| otp | 16384 | 1000 | 7.79 | 0.02 | 0.09 | 22.75 | 30.66 (p95 33.48) |
| approval | 1024 | 1000 | 7.45 | 0.02 | 0.08 | 5.60 | 13.15 (p95 13.55) |
| direct | 1024 | 1000 | 7.37 | 0.02 | 0.08 | 5.61 | 13.09 (p95 13.28) |
| approval | 16384 | 1000 | 7.69 | 0.02 | 0.09 | 28.07 | 35.87 (p95 32.48) |
| approval | 128 | 1000 | 7.35 | 0.02 | 0.08 | 4.52 | 11.97 (p95 12.07) |
| anon | 1024 | 1000 | 7.63 | 9.25 | 0.09 | 5.65 | 22.61 (p95 24.06) |
| otp | 1024 | 1000 | 7.43 | 0.02 | 0.09 | 5.62 | 13.16 (p95 13.72) |
| anon | 16384 | 1000 | 7.81 | 130.71 | 0.10 | 22.16 | 160.79 (p95 169.13) |
| direct | 128 | 1000 | 7.33 | 0.02 | 0.08 | 4.52 | 11.96 (p95 12.21) |
| otp | 128 | 1000 | 7.39 | 0.02 | 0.08 | 4.61 | 12.10 (p95 12.78) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
