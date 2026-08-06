# Latency decomposition (thesis §3.9.1, Equation 1)

Gateway-introduced latency per `vault.read`, mean microseconds (p95 in parentheses for total). The external legs `T_wan` and `T_inference` are not gateway-observable and are excluded.

| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |
|---|---|---|---|---|---|---|---|
| otp | 128 | 1000 | 7.64 | 0.02 | 0.09 | 4.73 | 12.48 (p95 12.73) |
| anon | 16384 | 1000 | 10.02 | 127.47 | 0.10 | 21.87 | 159.46 (p95 167.00) |
| otp | 1024 | 1000 | 7.27 | 0.02 | 0.09 | 5.55 | 12.92 (p95 14.10) |
| direct | 128 | 1000 | 7.22 | 0.02 | 0.09 | 4.44 | 11.77 (p95 12.74) |
| otp | 16384 | 1000 | 8.66 | 0.02 | 0.10 | 21.53 | 30.31 (p95 31.22) |
| approval | 16384 | 1000 | 8.07 | 0.02 | 0.09 | 21.58 | 29.76 (p95 31.65) |
| approval | 1024 | 1000 | 7.23 | 0.02 | 0.08 | 5.48 | 12.81 (p95 13.47) |
| anon | 1024 | 1000 | 7.34 | 9.07 | 0.10 | 5.48 | 21.99 (p95 23.18) |
| direct | 16384 | 1000 | 8.18 | 0.02 | 0.09 | 21.55 | 29.84 (p95 31.81) |
| approval | 128 | 1000 | 7.26 | 0.02 | 0.09 | 4.50 | 11.87 (p95 12.98) |
| direct | 1024 | 1000 | 7.35 | 0.02 | 0.09 | 5.55 | 13.01 (p95 14.12) |
| anon | 128 | 1000 | 7.46 | 1.70 | 0.09 | 4.52 | 13.77 (p95 15.11) |

*T_hitl is measured with an auto-allow controller and therefore reflects only the gateway's dispatch overhead, not human reaction time. In production T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be treated as an external parameter.*
