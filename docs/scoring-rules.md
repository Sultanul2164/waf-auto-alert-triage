# Scoring rules

Every alert (one source IP, one burst) is scored from 0 to 100 by `code/03-score-alert.js`. The score and a plain-language `reasons` list are stored on the alert, so every verdict can be audited.

## Rules

| # | Rule | Points |
|---|---|---|
| 1 | Worst attack type in the group (see table below) | up to 50 |
| 2 | Several different attack types from one IP | +5 per extra type |
| 3 | Volume: 5+ events / 10+ events / 50+ events | +10 / +15 / +25 |
| 4 | 3 or more distinct IPs from the same /24 in the dataset | +15 |
| 5 | AbuseIPDB confidence 40+ / 80+ | +20 / +40 |
| 6 | Target policy name contains "prod" | +5 |

### Attack type points

| Sub type | Points |
|---|---|
| SQL injection, XSS, traversal, command injection, RCE, shell (keyword match) | 50 |
| Generic Attacks (Extended) | 35 |
| Information Disclosure | 30 |
| Illegal HTTP Version | 20 |
| Header Value Length Violation | 15 |
| HTTP Parsing Error | 10 |
| HTTP Duplicated Parameter Name | 10 |
| GEO IP policy hit (N/A) | 10 |
| Missing POST Content Type | 5 |
| Unknown type | 15 |

## Levels

| Score | Level | What happens |
|---|---|---|
| 70+ | high | Sent to the AI for a summary |
| 45 to 69 | medium | Sent to the AI for a summary |
| 25 to 44 | low | Not sent to the AI |
| below 25 | ignore | Not sent to the AI |

## Tuning

The weights are a starting point. Run the workflow on a few days of your own logs, compare its levels with your own judgment, and adjust the numbers in `TYPE_POINTS` and the thresholds. Add your own scanners to `ALLOWLIST` in the Group node first, since they are usually the biggest source of false positives.
