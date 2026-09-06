# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.44 | 0.02 | 0.08 | 4.60 | 12.13 (p95 12.68) |
| direct | 1024 | 1000 | 7.46 | 0.04 | 0.09 | 5.68 | 13.27 (p95 13.46) |
| direct | 16384 | 1000 | 7.84 | 0.02 | 0.08 | 29.17 | 37.12 (p95 31.66) |
| approval | 128 | 1000 | 7.54 | 0.02 | 0.14 | 4.64 | 12.34 (p95 15.73) |
| approval | 1024 | 1000 | 7.36 | 0.02 | 0.08 | 5.60 | 13.06 (p95 13.20) |
| approval | 16384 | 1000 | 7.63 | 0.02 | 0.08 | 28.24 | 35.97 (p95 32.43) |
| otp | 128 | 1000 | 7.31 | 0.02 | 0.08 | 4.44 | 11.85 (p95 12.01) |
| otp | 1024 | 1000 | 7.38 | 0.02 | 0.07 | 5.63 | 13.11 (p95 13.28) |
| otp | 16384 | 1000 | 7.58 | 0.03 | 0.08 | 22.59 | 30.28 (p95 32.07) |
| anon | 128 | 1000 | 7.55 | 1.70 | 0.08 | 4.65 | 13.99 (p95 14.90) |
| anon | 1024 | 1000 | 7.39 | 9.39 | 0.09 | 5.60 | 22.47 (p95 23.37) |
| anon | 16384 | 1000 | 7.71 | 129.99 | 0.10 | 22.43 | 160.23 (p95 165.52) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
