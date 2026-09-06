# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| direct | 16384 | 1000 | 8.15 | 0.02 | 0.08 | 29.56 | 37.82 (p95 38.04) |
| direct | 1024 | 1000 | 7.19 | 0.02 | 0.07 | 5.43 | 12.71 (p95 12.94) |
| approval | 16384 | 1000 | 7.64 | 0.02 | 0.08 | 28.11 | 35.85 (p95 32.90) |
| approval | 1024 | 1000 | 7.42 | 0.02 | 0.07 | 5.67 | 13.18 (p95 14.21) |
| otp | 1024 | 1000 | 7.20 | 0.02 | 0.07 | 5.53 | 12.82 (p95 13.50) |
| approval | 128 | 1000 | 7.22 | 0.02 | 0.07 | 4.43 | 11.75 (p95 12.90) |
| anon | 128 | 1000 | 7.22 | 1.62 | 0.08 | 4.43 | 13.35 (p95 14.26) |
| otp | 16384 | 1000 | 7.40 | 0.02 | 0.07 | 21.98 | 29.47 (p95 31.07) |
| anon | 16384 | 1000 | 7.72 | 126.98 | 0.08 | 21.94 | 156.73 (p95 163.70) |
| otp | 128 | 1000 | 7.35 | 0.02 | 0.07 | 4.48 | 11.91 (p95 12.40) |
| direct | 128 | 1000 | 7.11 | 0.02 | 0.07 | 4.43 | 11.63 (p95 12.38) |
| anon | 1024 | 1000 | 7.43 | 9.04 | 0.08 | 5.52 | 22.07 (p95 23.29) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
