# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.40 | 0.02 | 0.08 | 4.61 | 12.11 (p95 12.41) |
| direct | 1024 | 1000 | 7.21 | 0.02 | 0.09 | 5.49 | 12.81 (p95 13.75) |
| direct | 16384 | 1000 | 9.06 | 0.02 | 0.08 | 21.77 | 30.94 (p95 31.29) |
| approval | 128 | 1000 | 7.07 | 0.02 | 0.08 | 4.36 | 11.52 (p95 12.07) |
| approval | 1024 | 1000 | 7.27 | 0.03 | 0.09 | 5.54 | 12.94 (p95 14.11) |
| approval | 16384 | 1000 | 8.08 | 0.02 | 0.09 | 21.55 | 29.74 (p95 31.36) |
| otp | 128 | 1000 | 7.17 | 0.02 | 0.07 | 4.44 | 11.71 (p95 12.41) |
| otp | 1024 | 1000 | 7.17 | 0.02 | 0.08 | 5.46 | 12.72 (p95 13.75) |
| otp | 16384 | 1000 | 8.61 | 0.02 | 0.08 | 21.46 | 30.17 (p95 31.18) |
| anon | 128 | 1000 | 7.19 | 1.65 | 0.09 | 4.41 | 13.34 (p95 13.81) |
| anon | 1024 | 1000 | 7.42 | 9.03 | 0.10 | 5.52 | 22.07 (p95 23.46) |
| anon | 16384 | 1000 | 8.84 | 126.32 | 0.09 | 21.44 | 156.70 (p95 163.26) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
