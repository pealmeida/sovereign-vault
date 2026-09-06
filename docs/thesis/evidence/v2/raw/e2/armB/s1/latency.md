# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.95 | 0.02 | 0.10 | 4.85 | 12.93 (p95 19.23) |
| direct | 1024 | 1000 | 7.35 | 0.02 | 0.09 | 5.59 | 13.06 (p95 13.41) |
| direct | 16384 | 1000 | 7.99 | 0.02 | 0.10 | 29.11 | 37.22 (p95 34.04) |
| approval | 128 | 1000 | 7.42 | 0.02 | 0.10 | 4.58 | 12.11 (p95 12.58) |
| approval | 1024 | 1000 | 7.30 | 0.02 | 0.09 | 5.59 | 13.00 (p95 13.20) |
| approval | 16384 | 1000 | 7.66 | 0.02 | 0.10 | 28.18 | 35.96 (p95 32.67) |
| otp | 128 | 1000 | 7.29 | 0.02 | 0.09 | 4.49 | 11.89 (p95 12.02) |
| otp | 1024 | 1000 | 7.42 | 0.02 | 0.10 | 5.64 | 13.18 (p95 13.89) |
| otp | 16384 | 1000 | 7.63 | 0.02 | 0.09 | 22.60 | 30.35 (p95 32.78) |
| anon | 128 | 1000 | 7.43 | 1.68 | 0.11 | 4.55 | 13.76 (p95 14.30) |
| anon | 1024 | 1000 | 7.46 | 9.16 | 0.10 | 5.55 | 22.27 (p95 23.08) |
| anon | 16384 | 1000 | 7.98 | 129.90 | 0.11 | 22.25 | 160.23 (p95 169.10) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
