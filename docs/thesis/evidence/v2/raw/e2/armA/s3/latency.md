# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 128 | 1000 | 7.47 | 0.02 | 0.07 | 4.59 | 12.16 (p95 13.32) |
| direct | 1024 | 1000 | 7.40 | 0.02 | 0.07 | 5.63 | 13.12 (p95 14.52) |
| direct | 16384 | 1000 | 9.33 | 0.02 | 0.08 | 22.12 | 31.55 (p95 34.86) |
| approval | 128 | 1000 | 7.16 | 0.02 | 0.07 | 4.39 | 11.64 (p95 12.01) |
| approval | 1024 | 1000 | 7.31 | 0.02 | 0.07 | 5.51 | 12.90 (p95 14.11) |
| approval | 16384 | 1000 | 8.05 | 0.02 | 0.07 | 21.38 | 29.51 (p95 30.58) |
| otp | 128 | 1000 | 7.25 | 0.02 | 0.07 | 4.44 | 11.77 (p95 12.93) |
| otp | 1024 | 1000 | 7.48 | 0.02 | 0.07 | 5.70 | 13.27 (p95 14.27) |
| otp | 16384 | 1000 | 8.49 | 0.02 | 0.07 | 21.36 | 29.94 (p95 30.49) |
| anon | 128 | 1000 | 7.37 | 1.64 | 0.08 | 4.49 | 13.57 (p95 14.68) |
| anon | 1024 | 1000 | 7.49 | 9.11 | 0.08 | 5.55 | 22.22 (p95 23.61) |
| anon | 16384 | 1000 | 8.81 | 126.93 | 0.08 | 21.39 | 157.22 (p95 161.49) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
