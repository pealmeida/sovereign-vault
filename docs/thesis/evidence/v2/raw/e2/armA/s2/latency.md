# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.57 | 0.02 | 0.08 | 4.70 | 12.38 (p95 13.45) |
| direct | 1024 | 1000 | 7.16 | 0.02 | 0.08 | 5.43 | 12.69 (p95 12.94) |
| direct | 16384 | 1000 | 9.42 | 0.02 | 0.09 | 22.24 | 31.77 (p95 39.10) |
| approval | 128 | 1000 | 7.19 | 0.02 | 0.08 | 4.39 | 11.68 (p95 12.04) |
| approval | 1024 | 1000 | 7.17 | 0.02 | 0.08 | 5.45 | 12.71 (p95 12.98) |
| approval | 16384 | 1000 | 8.20 | 0.02 | 0.09 | 21.56 | 29.88 (p95 33.45) |
| otp | 128 | 1000 | 7.14 | 0.02 | 0.07 | 4.36 | 11.60 (p95 11.98) |
| otp | 1024 | 1000 | 7.14 | 0.02 | 0.07 | 5.43 | 12.66 (p95 12.96) |
| otp | 16384 | 1000 | 8.55 | 0.02 | 0.08 | 21.50 | 30.15 (p95 31.32) |
| anon | 128 | 1000 | 7.40 | 1.68 | 0.08 | 4.50 | 13.67 (p95 14.83) |
| anon | 1024 | 1000 | 7.59 | 9.41 | 0.09 | 5.67 | 22.76 (p95 25.07) |
| anon | 16384 | 1000 | 8.96 | 127.65 | 0.10 | 21.59 | 158.29 (p95 167.98) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
