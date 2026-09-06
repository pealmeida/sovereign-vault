# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 128 | 1000 | 7.77 | 1.81 | 0.10 | 4.74 | 14.42 (p95 15.22) |
| otp | 16384 | 1000 | 10.31 | 0.02 | 0.10 | 23.28 | 33.71 (p95 35.31) |
| approval | 128 | 1000 | 7.48 | 0.02 | 0.09 | 4.61 | 12.21 (p95 12.62) |
| direct | 16384 | 1000 | 8.58 | 0.02 | 0.10 | 22.51 | 31.22 (p95 33.29) |
| approval | 1024 | 1000 | 7.60 | 0.02 | 0.10 | 5.77 | 13.48 (p95 13.72) |
| direct | 128 | 1000 | 7.54 | 0.02 | 0.09 | 4.72 | 12.37 (p95 12.53) |
| otp | 1024 | 1000 | 7.93 | 0.02 | 0.10 | 5.99 | 14.04 (p95 18.25) |
| direct | 1024 | 1000 | 7.73 | 0.02 | 0.10 | 5.91 | 13.76 (p95 18.03) |
| anon | 1024 | 1000 | 7.29 | 8.99 | 0.10 | 5.53 | 21.90 (p95 23.39) |
| anon | 16384 | 1000 | 8.84 | 127.21 | 0.11 | 21.54 | 157.69 (p95 166.04) |
| approval | 16384 | 1000 | 8.06 | 0.02 | 0.10 | 21.46 | 29.64 (p95 32.18) |
| otp | 128 | 1000 | 7.14 | 0.02 | 0.09 | 4.43 | 11.68 (p95 12.54) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
