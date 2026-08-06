# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.64 | 0.04 | 0.09 | 4.78 | 12.54 (p95 15.03) |
| direct | 1024 | 1000 | 7.42 | 0.02 | 0.08 | 5.61 | 13.13 (p95 14.38) |
| direct | 16384 | 1000 | 9.13 | 0.02 | 0.09 | 21.86 | 31.09 (p95 31.43) |
| approval | 128 | 1000 | 7.08 | 0.02 | 0.07 | 4.39 | 11.56 (p95 11.75) |
| approval | 1024 | 1000 | 7.17 | 0.03 | 0.08 | 5.49 | 12.76 (p95 13.84) |
| approval | 16384 | 1000 | 8.28 | 0.02 | 0.09 | 21.90 | 30.29 (p95 33.38) |
| otp | 128 | 1000 | 7.10 | 0.02 | 0.08 | 4.40 | 11.60 (p95 11.86) |
| otp | 1024 | 1000 | 7.26 | 0.02 | 0.08 | 5.55 | 12.91 (p95 14.38) |
| otp | 16384 | 1000 | 8.46 | 0.02 | 0.08 | 21.37 | 29.94 (p95 31.36) |
| anon | 128 | 1000 | 7.13 | 1.63 | 0.09 | 4.41 | 13.26 (p95 13.57) |
| anon | 1024 | 1000 | 7.32 | 9.04 | 0.08 | 5.48 | 21.92 (p95 23.31) |
| anon | 16384 | 1000 | 8.93 | 127.75 | 0.09 | 21.50 | 158.27 (p95 172.53) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
