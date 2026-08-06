# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.43 | 0.02 | 0.08 | 4.64 | 12.17 (p95 13.05) |
| direct | 1024 | 1000 | 7.54 | 0.02 | 0.08 | 5.71 | 13.35 (p95 13.67) |
| direct | 16384 | 1000 | 10.69 | 0.04 | 0.13 | 35.21 | 46.06 (p95 50.84) |
| approval | 128 | 1000 | 7.66 | 0.02 | 0.09 | 4.75 | 12.52 (p95 15.61) |
| approval | 1024 | 1000 | 7.48 | 0.02 | 0.08 | 5.69 | 13.27 (p95 13.45) |
| approval | 16384 | 1000 | 8.37 | 0.03 | 0.09 | 29.76 | 38.25 (p95 47.25) |
| otp | 128 | 1000 | 12.93 | 0.03 | 0.13 | 7.46 | 20.55 (p95 23.13) |
| otp | 1024 | 1000 | 7.49 | 0.02 | 0.08 | 5.71 | 13.30 (p95 13.57) |
| otp | 16384 | 1000 | 7.68 | 0.02 | 0.08 | 22.90 | 30.69 (p95 32.33) |
| anon | 128 | 1000 | 7.54 | 1.70 | 0.08 | 4.62 | 13.95 (p95 14.30) |
| anon | 1024 | 1000 | 7.74 | 9.41 | 0.08 | 5.75 | 22.99 (p95 24.24) |
| anon | 16384 | 1000 | 8.15 | 132.86 | 0.10 | 22.82 | 163.93 (p95 171.23) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
