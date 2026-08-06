# Adversarial block-rate (thesis §3.9.2)

**Block rate:** 10/10 attacks blocked (100.0%). **Availability:** 2/2 legitimate requests allowed (100.0%). **Transport errors (excluded from both rates):** 0. 14 events written to the tamper-evident audit log.

| Probe | Class | Description | Blocked | Expected | Verdict |
|---|---|---|---|---|---|
| A1 | attack | read secrets/api.key outside scope | yes | block | PASS |
| A2 | attack | read personal-id outside scope | yes | block | PASS |
| A3 | attack | write to public (read-only scope) | yes | block | PASS |
| A4 | attack | path traversal in file_name | yes | block | PASS |
| A5 | attack | path traversal in container | yes | block | PASS |
| A6 | attack | enumerate all containers | yes | block | PASS |
| A7 | attack | delete a secret outside scope | yes | block | PASS |
| A8 | attack | unscoped Default agent reads secret (no consent) | yes | block | PASS |
| A9 | attack | read NATIVE (reserved-mode) container | yes | block | PASS |
| A10 | attack | create NATIVE (reserved-mode) container | yes | block | PASS |
| C1 | control | read own public file (in scope) | no | allow | PASS |
| C2 | control | list files in public (in scope) | no | allow | PASS |
