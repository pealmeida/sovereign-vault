# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 16384 | 1000 | 8.34 | 130.82 | 0.11 | 22.81 | 162.07 (p95 170.16) |
| otp | 1024 | 1000 | 7.58 | 0.02 | 0.08 | 5.75 | 13.44 (p95 14.12) |
| approval | 128 | 1000 | 7.30 | 0.02 | 0.09 | 4.50 | 11.91 (p95 12.08) |
| approval | 16384 | 1000 | 7.80 | 0.02 | 0.09 | 27.98 | 35.90 (p95 33.50) |
| direct | 1024 | 1000 | 7.42 | 0.02 | 0.09 | 5.60 | 13.13 (p95 13.30) |
| otp | 128 | 1000 | 7.41 | 0.02 | 0.11 | 4.54 | 12.08 (p95 12.40) |
| otp | 16384 | 1000 | 7.67 | 0.02 | 0.08 | 22.27 | 30.05 (p95 32.85) |
| direct | 16384 | 1000 | 7.83 | 0.02 | 0.09 | 28.47 | 36.41 (p95 35.17) |
| anon | 128 | 1000 | 7.53 | 1.64 | 0.08 | 4.53 | 13.80 (p95 14.95) |
| anon | 1024 | 1000 | 7.61 | 9.26 | 0.09 | 5.61 | 22.57 (p95 23.51) |
| approval | 1024 | 1000 | 7.42 | 0.02 | 0.08 | 5.57 | 13.10 (p95 13.26) |
| direct | 128 | 1000 | 7.38 | 0.02 | 0.08 | 4.54 | 12.02 (p95 12.39) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
