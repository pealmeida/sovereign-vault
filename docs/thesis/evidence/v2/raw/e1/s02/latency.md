# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 128 | 1000 | 7.60 | 1.67 | 0.09 | 4.60 | 13.96 (p95 14.91) |
| otp | 16384 | 1000 | 8.01 | 0.02 | 0.08 | 22.59 | 30.70 (p95 31.26) |
| approval | 16384 | 1000 | 7.83 | 0.02 | 0.08 | 28.54 | 36.47 (p95 32.86) |
| direct | 128 | 1000 | 7.37 | 0.02 | 0.08 | 4.54 | 12.01 (p95 12.24) |
| approval | 1024 | 1000 | 7.47 | 0.02 | 0.08 | 5.63 | 13.21 (p95 13.69) |
| approval | 128 | 1000 | 7.35 | 0.02 | 0.08 | 4.49 | 11.94 (p95 12.36) |
| otp | 1024 | 1000 | 7.50 | 0.02 | 0.08 | 5.69 | 13.29 (p95 13.71) |
| direct | 16384 | 1000 | 7.64 | 0.02 | 0.08 | 28.27 | 36.01 (p95 32.02) |
| anon | 1024 | 1000 | 7.58 | 9.19 | 0.09 | 5.69 | 22.54 (p95 23.91) |
| anon | 16384 | 1000 | 8.00 | 130.25 | 0.09 | 22.48 | 160.83 (p95 167.90) |
| direct | 1024 | 1000 | 7.43 | 0.02 | 0.08 | 5.64 | 13.18 (p95 13.46) |
| otp | 128 | 1000 | 7.28 | 0.02 | 0.08 | 4.51 | 11.88 (p95 12.10) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
