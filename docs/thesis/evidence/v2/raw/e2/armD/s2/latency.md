# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| approval | 1024 | 1000 | 7.62 | 0.02 | 0.10 | 5.86 | 13.60 (p95 14.98) |
| anon | 128 | 1000 | 7.69 | 1.74 | 0.10 | 4.69 | 14.22 (p95 15.29) |
| otp | 16384 | 1000 | 8.17 | 0.02 | 0.10 | 23.27 | 31.56 (p95 32.62) |
| anon | 1024 | 1000 | 8.07 | 9.98 | 0.11 | 6.03 | 24.18 (p95 31.11) |
| anon | 16384 | 1000 | 8.29 | 135.65 | 0.11 | 23.17 | 167.22 (p95 173.74) |
| direct | 128 | 1000 | 7.60 | 0.02 | 0.09 | 4.69 | 12.40 (p95 12.68) |
| direct | 16384 | 1000 | 7.85 | 0.02 | 0.09 | 28.96 | 36.92 (p95 32.65) |
| approval | 16384 | 1000 | 7.87 | 0.02 | 0.09 | 28.80 | 36.79 (p95 32.72) |
| otp | 128 | 1000 | 7.60 | 0.02 | 0.10 | 4.65 | 12.37 (p95 12.61) |
| direct | 1024 | 1000 | 7.61 | 0.02 | 0.09 | 5.75 | 13.48 (p95 13.68) |
| approval | 128 | 1000 | 7.51 | 0.02 | 0.08 | 4.60 | 12.22 (p95 12.50) |
| otp | 1024 | 1000 | 7.66 | 0.02 | 0.09 | 5.80 | 13.58 (p95 14.05) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
