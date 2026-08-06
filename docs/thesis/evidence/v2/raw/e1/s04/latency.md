# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| approval | 1024 | 1000 | 7.81 | 0.02 | 0.09 | 5.88 | 13.81 (p95 19.59) |
| otp | 128 | 1000 | 7.33 | 0.02 | 0.09 | 4.47 | 11.91 (p95 12.04) |
| anon | 128 | 1000 | 7.54 | 1.69 | 0.11 | 4.57 | 13.91 (p95 15.21) |
| anon | 16384 | 1000 | 8.38 | 129.59 | 0.10 | 22.89 | 160.96 (p95 168.47) |
| otp | 16384 | 1000 | 7.64 | 0.02 | 0.09 | 22.16 | 29.91 (p95 32.07) |
| approval | 128 | 1000 | 7.31 | 0.02 | 0.09 | 4.49 | 11.90 (p95 12.02) |
| otp | 1024 | 1000 | 7.36 | 0.02 | 0.08 | 5.56 | 13.02 (p95 13.22) |
| approval | 16384 | 1000 | 7.72 | 0.02 | 0.09 | 28.15 | 35.98 (p95 32.23) |
| direct | 1024 | 1000 | 7.43 | 0.02 | 0.09 | 5.63 | 13.17 (p95 14.19) |
| anon | 1024 | 1000 | 7.49 | 9.12 | 0.09 | 5.58 | 22.27 (p95 22.97) |
| direct | 16384 | 1000 | 7.63 | 0.02 | 0.09 | 27.88 | 35.62 (p95 31.88) |
| direct | 128 | 1000 | 7.24 | 0.02 | 0.09 | 4.53 | 11.87 (p95 11.94) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
