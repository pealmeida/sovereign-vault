# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.58 | 0.02 | 0.09 | 4.69 | 12.37 (p95 12.97) |
| approval | 16384 | 1000 | 8.26 | 0.02 | 0.09 | 29.11 | 37.50 (p95 33.12) |
| otp | 1024 | 1000 | 7.55 | 0.03 | 0.09 | 5.76 | 13.42 (p95 13.78) |
| otp | 16384 | 1000 | 7.86 | 0.02 | 0.10 | 23.04 | 31.02 (p95 34.68) |
| anon | 128 | 1000 | 7.47 | 1.68 | 0.08 | 4.54 | 13.78 (p95 13.94) |
| direct | 1024 | 1000 | 8.43 | 0.03 | 0.10 | 6.27 | 14.83 (p95 21.54) |
| otp | 128 | 1000 | 7.51 | 0.02 | 0.08 | 4.62 | 12.23 (p95 12.35) |
| direct | 16384 | 1000 | 8.24 | 0.02 | 0.09 | 29.52 | 37.88 (p95 42.48) |
| approval | 1024 | 1000 | 7.48 | 0.02 | 0.08 | 5.66 | 13.25 (p95 13.41) |
| anon | 1024 | 1000 | 7.61 | 9.27 | 0.09 | 5.64 | 22.61 (p95 23.10) |
| anon | 16384 | 1000 | 7.91 | 130.38 | 0.09 | 22.50 | 160.89 (p95 164.49) |
| approval | 128 | 1000 | 7.38 | 0.02 | 0.08 | 4.55 | 12.04 (p95 12.17) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
