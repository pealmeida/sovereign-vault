# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 1024 | 1000 | 7.57 | 0.02 | 0.09 | 5.76 | 13.44 (p95 13.70) |
| direct | 128 | 1000 | 7.20 | 0.02 | 0.08 | 4.48 | 11.78 (p95 12.00) |
| direct | 16384 | 1000 | 7.80 | 0.02 | 0.08 | 28.92 | 36.83 (p95 31.99) |
| approval | 1024 | 1000 | 7.43 | 0.02 | 0.09 | 5.62 | 13.16 (p95 13.40) |
| anon | 1024 | 1000 | 7.51 | 9.41 | 0.09 | 5.62 | 22.63 (p95 24.77) |
| approval | 128 | 1000 | 7.33 | 0.02 | 0.08 | 4.56 | 11.98 (p95 12.22) |
| otp | 128 | 1000 | 7.35 | 0.02 | 0.08 | 4.50 | 11.95 (p95 12.15) |
| approval | 16384 | 1000 | 7.56 | 0.02 | 0.09 | 28.07 | 35.74 (p95 31.48) |
| otp | 16384 | 1000 | 7.54 | 0.02 | 0.09 | 22.49 | 30.14 (p95 31.20) |
| otp | 1024 | 1000 | 7.42 | 0.02 | 0.08 | 5.62 | 13.14 (p95 13.51) |
| anon | 16384 | 1000 | 7.91 | 133.12 | 0.10 | 22.55 | 163.68 (p95 170.39) |
| anon | 128 | 1000 | 7.42 | 1.66 | 0.09 | 4.56 | 13.72 (p95 14.04) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
