# Trust Score Simulation

## Date: 13-06-2026

## Formula (Tiya's Trust Formula)
## Rogue Agent Simulation

| Step | Event | Trust Score | Role |
|------|-------|-------------|------|
| Start | — | 1.0 | AGENT |
| 1 | injection_attempt | 0.92 | AGENT |
| 2 | injection_attempt | 0.84 | AGENT |
| 3 | injection_attempt | 0.76 | AGENT |
| 4 | injection_attempt | 0.68 | AGENT |
| 5 | injection_attempt | 0.60 | AGENT |
| 6 | poisoning_attempt | 0.50 | AGENT |
| 7 | poisoning_attempt | 0.40 | AGENT |
| 8 | poisoning_attempt | 0.20 | READONLY ⚠️ |

## Conclusion
After 5 injection attempts and 3 poisoning attempts, the rogue agent's
trust score dropped to 0.20 — below the 0.3 threshold — and was
automatically downgraded to READONLY, preventing any further
write or delete operations.