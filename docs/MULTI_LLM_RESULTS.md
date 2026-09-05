# Multi-LLM Prompt-Injection Evaluation

Evaluated against `tests/test_prompts.json` (50 prompts, 25 attacks / 25 benign).

| Provider | Status | TP | TN | FP | FN | Precision | Recall | F1 | Avg Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|
| groq | evaluated | 25 | 25 | 0 | 0 | 1.0 | 1.0 | 1.0 | 2199.3 |
| openai | PENDING — REAL EVALUATION REQUIRED (no API key configured) | - | - | - | - | - | - | - | - |
| anthropic | PENDING — REAL EVALUATION REQUIRED (no API key configured) | - | - | - | - | - | - | - | - |
| gemini | PENDING — REAL EVALUATION REQUIRED (no API key configured) | - | - | - | - | - | - | - | - |

PENDING rows have no API key configured in `.env` — per project policy, no numbers are invented for a provider that was never actually called.
