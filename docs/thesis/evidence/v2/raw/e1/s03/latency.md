# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 1024 | 1000 | 7.78 | 9.62 | 0.09 | 5.89 | 23.38 (p95 25.70) |
| approval | 16384 | 1000 | 8.07 | 0.02 | 0.08 | 28.75 | 36.93 (p95 32.16) |
| direct | 1024 | 1000 | 7.35 | 0.02 | 0.08 | 5.59 | 13.05 (p95 13.38) |
| anon | 128 | 1000 | 7.57 | 1.68 | 0.09 | 4.61 | 13.96 (p95 14.47) |
| direct | 128 | 1000 | 7.49 | 0.02 | 0.08 | 4.62 | 12.20 (p95 13.15) |
| direct | 16384 | 1000 | 7.63 | 0.02 | 0.08 | 28.33 | 36.07 (p95 32.87) |
| otp | 16384 | 1000 | 7.65 | 0.02 | 0.08 | 22.55 | 30.31 (p95 32.27) |
| otp | 1024 | 1000 | 7.45 | 0.02 | 0.08 | 5.68 | 13.23 (p95 14.62) |
| approval | 1024 | 1000 | 7.31 | 0.02 | 0.08 | 5.57 | 12.98 (p95 13.24) |
| anon | 16384 | 1000 | 7.87 | 131.03 | 0.10 | 22.30 | 161.30 (p95 168.25) |
| otp | 128 | 1000 | 7.39 | 0.02 | 0.08 | 4.52 | 12.02 (p95 12.19) |
| approval | 128 | 1000 | 7.31 | 0.02 | 0.07 | 4.51 | 11.91 (p95 12.17) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
