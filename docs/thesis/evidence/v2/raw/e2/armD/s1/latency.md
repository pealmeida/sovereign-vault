# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| otp | 16384 | 1000 | 7.85 | 0.02 | 0.10 | 22.39 | 30.37 (p95 31.16) |
| anon | 16384 | 1000 | 7.78 | 127.04 | 0.10 | 22.04 | 156.95 (p95 164.58) |
| approval | 128 | 1000 | 7.38 | 0.02 | 0.09 | 4.60 | 12.09 (p95 12.89) |
| approval | 16384 | 1000 | 7.54 | 0.02 | 0.09 | 27.48 | 35.14 (p95 31.62) |
| otp | 128 | 1000 | 7.26 | 0.02 | 0.09 | 4.48 | 11.84 (p95 12.14) |
| anon | 128 | 1000 | 7.44 | 1.67 | 0.09 | 4.54 | 13.73 (p95 14.94) |
| otp | 1024 | 1000 | 7.28 | 0.02 | 0.09 | 5.54 | 12.93 (p95 13.51) |
| direct | 16384 | 1000 | 7.43 | 0.02 | 0.09 | 27.64 | 35.18 (p95 31.11) |
| anon | 1024 | 1000 | 7.65 | 9.36 | 0.09 | 5.72 | 22.83 (p95 25.02) |
| direct | 128 | 1000 | 7.27 | 0.02 | 0.09 | 4.52 | 11.90 (p95 13.04) |
| direct | 1024 | 1000 | 7.26 | 0.02 | 0.09 | 5.55 | 12.91 (p95 14.05) |
| approval | 1024 | 1000 | 7.29 | 0.02 | 0.09 | 5.54 | 12.93 (p95 13.33) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
