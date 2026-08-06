# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| approval | 16384 | 1000 | 14.48 | 0.02 | 0.08 | 22.86 | 37.44 (p95 33.01) |
| anon | 128 | 1000 | 7.52 | 1.73 | 0.07 | 4.59 | 13.91 (p95 14.22) |
| direct | 16384 | 1000 | 8.65 | 0.02 | 0.08 | 22.59 | 31.34 (p95 34.36) |
| otp | 16384 | 1000 | 8.96 | 0.02 | 0.08 | 22.47 | 31.53 (p95 33.55) |
| direct | 128 | 1000 | 7.34 | 0.02 | 0.07 | 4.55 | 11.98 (p95 12.14) |
| anon | 16384 | 1000 | 9.13 | 133.10 | 0.09 | 22.35 | 164.67 (p95 169.86) |
| otp | 128 | 1000 | 7.45 | 0.02 | 0.07 | 4.56 | 12.10 (p95 12.29) |
| anon | 1024 | 1000 | 7.63 | 9.43 | 0.08 | 5.71 | 22.85 (p95 23.73) |
| direct | 1024 | 1000 | 7.58 | 0.02 | 0.07 | 5.75 | 13.42 (p95 13.76) |
| otp | 1024 | 1000 | 7.54 | 0.02 | 0.07 | 5.69 | 13.32 (p95 13.49) |
| approval | 1024 | 1000 | 7.47 | 0.02 | 0.07 | 5.65 | 13.22 (p95 13.47) |
| approval | 128 | 1000 | 7.42 | 0.02 | 0.07 | 4.57 | 12.08 (p95 12.29) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
