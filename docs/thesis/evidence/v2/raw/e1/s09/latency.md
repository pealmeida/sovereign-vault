# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| anon | 16384 | 1000 | 8.13 | 128.49 | 0.10 | 22.84 | 159.56 (p95 162.62) |
| approval | 1024 | 1000 | 7.34 | 0.02 | 0.10 | 5.68 | 13.14 (p95 13.28) |
| otp | 16384 | 1000 | 7.86 | 0.02 | 0.10 | 22.85 | 30.83 (p95 39.84) |
| anon | 1024 | 1000 | 7.52 | 9.21 | 0.10 | 5.66 | 22.48 (p95 23.04) |
| approval | 16384 | 1000 | 7.78 | 0.02 | 0.10 | 28.05 | 35.96 (p95 32.01) |
| direct | 1024 | 1000 | 7.26 | 0.02 | 0.09 | 5.60 | 12.97 (p95 13.36) |
| otp | 128 | 1000 | 7.39 | 0.02 | 0.09 | 4.49 | 11.99 (p95 12.27) |
| otp | 1024 | 1000 | 7.34 | 0.02 | 0.09 | 5.60 | 13.06 (p95 13.18) |
| direct | 128 | 1000 | 7.27 | 0.02 | 0.10 | 4.57 | 11.96 (p95 12.06) |
| approval | 128 | 1000 | 7.37 | 0.02 | 0.09 | 4.51 | 11.99 (p95 12.07) |
| direct | 16384 | 1000 | 7.67 | 0.02 | 0.10 | 28.59 | 36.38 (p95 31.70) |
| anon | 128 | 1000 | 7.42 | 1.75 | 0.09 | 4.56 | 13.82 (p95 13.98) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
