# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| approval | 16384 | 1000 | 8.17 | 0.02 | 0.08 | 29.07 | 37.35 (p95 33.19) |
| otp | 16384 | 1000 | 7.57 | 0.02 | 0.09 | 22.21 | 29.88 (p95 32.71) |
| approval | 1024 | 1000 | 7.74 | 0.02 | 0.09 | 5.80 | 13.64 (p95 17.52) |
| direct | 128 | 1000 | 7.50 | 0.02 | 0.08 | 4.58 | 12.18 (p95 13.40) |
| anon | 1024 | 1000 | 7.30 | 8.94 | 0.09 | 5.47 | 21.80 (p95 23.21) |
| anon | 128 | 1000 | 7.11 | 1.58 | 0.08 | 4.35 | 13.12 (p95 13.38) |
| approval | 128 | 1000 | 7.01 | 0.02 | 0.08 | 4.34 | 11.45 (p95 11.67) |
| otp | 1024 | 1000 | 7.13 | 0.02 | 0.08 | 5.47 | 12.70 (p95 12.95) |
| direct | 1024 | 1000 | 7.18 | 0.02 | 0.08 | 5.51 | 12.79 (p95 13.83) |
| direct | 16384 | 1000 | 7.45 | 0.02 | 0.10 | 27.75 | 35.33 (p95 32.04) |
| anon | 16384 | 1000 | 7.55 | 127.15 | 0.09 | 21.85 | 156.63 (p95 163.37) |
| otp | 128 | 1000 | 7.05 | 0.02 | 0.08 | 4.36 | 11.51 (p95 11.71) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
