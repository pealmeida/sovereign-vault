# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| otp | 16384 | 1000 | 8.13 | 0.02 | 0.10 | 23.16 | 31.41 (p95 32.93) |
| approval | 16384 | 1000 | 7.82 | 0.02 | 0.11 | 28.81 | 36.75 (p95 32.70) |
| otp | 128 | 1000 | 7.55 | 0.02 | 0.10 | 4.59 | 12.26 (p95 12.55) |
| anon | 16384 | 1000 | 8.14 | 133.74 | 0.11 | 22.91 | 164.90 (p95 172.49) |
| direct | 1024 | 1000 | 7.87 | 0.02 | 0.10 | 5.91 | 13.90 (p95 17.66) |
| approval | 128 | 1000 | 7.65 | 0.02 | 0.10 | 4.70 | 12.47 (p95 12.90) |
| anon | 1024 | 1000 | 7.89 | 9.55 | 0.10 | 5.78 | 23.33 (p95 25.06) |
| otp | 1024 | 1000 | 7.71 | 0.02 | 0.09 | 5.83 | 13.65 (p95 14.82) |
| approval | 1024 | 1000 | 7.60 | 0.02 | 0.09 | 5.74 | 13.45 (p95 13.73) |
| direct | 16384 | 1000 | 7.85 | 0.02 | 0.09 | 28.90 | 36.87 (p95 33.23) |
| anon | 128 | 1000 | 7.72 | 1.74 | 0.10 | 4.64 | 14.20 (p95 15.04) |
| direct | 128 | 1000 | 7.61 | 0.02 | 0.09 | 4.67 | 12.39 (p95 13.17) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
