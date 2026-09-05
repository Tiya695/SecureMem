"""Phase 13 — run tests/test_prompts.json through every available LLM connector and compute
real Precision/Recall/F1/avg latency. Never fabricates a number for an unavailable provider —
those are marked PENDING in the output.

Usage:
    python testing/eval_all_models.py
"""
import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from testing.llm_connectors import CONNECTORS

PROMPTS_PATH = os.path.join(os.path.dirname(__file__), "..", "tests", "test_prompts.json")
RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "MULTI_LLM_RESULTS.md")


def evaluate_provider(name: str, connector, prompts: list) -> dict:
    tp = tn = fp = fn = 0
    latencies = []
    unavailable = False

    for item in prompts:
        result = connector(item["prompt"])
        if result.get("status") == "connector_unavailable":
            unavailable = True
            break

        predicted = bool(result.get("is_injection"))
        actual = bool(item["label"])
        latencies.append(result.get("latency_ms", 0.0))

        if predicted and actual:
            tp += 1
        elif not predicted and not actual:
            tn += 1
        elif predicted and not actual:
            fp += 1
        else:
            fn += 1

    if unavailable:
        return {"provider": name, "status": "PENDING — REAL EVALUATION REQUIRED (no API key configured)"}

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "provider": name,
        "status": "evaluated",
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "avg_latency_ms": round(avg_latency, 1),
    }


def main() -> None:
    with open(PROMPTS_PATH, encoding="utf-8") as f:
        prompts = json.load(f)

    results = [evaluate_provider(name, fn, prompts) for name, fn in CONNECTORS.items()]

    lines = [
        "# Multi-LLM Prompt-Injection Evaluation",
        "",
        f"Evaluated against `tests/test_prompts.json` ({len(prompts)} prompts, "
        f"{sum(1 for p in prompts if p['label'])} attacks / {sum(1 for p in prompts if not p['label'])} benign).",
        "",
        "| Provider | Status | TP | TN | FP | FN | Precision | Recall | F1 | Avg Latency (ms) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if r["status"] != "evaluated":
            lines.append(f"| {r['provider']} | {r['status']} | - | - | - | - | - | - | - | - |")
        else:
            lines.append(
                f"| {r['provider']} | evaluated | {r['tp']} | {r['tn']} | {r['fp']} | {r['fn']} | "
                f"{r['precision']} | {r['recall']} | {r['f1']} | {r['avg_latency_ms']} |"
            )
    lines.append("")
    lines.append(
        "PENDING rows have no API key configured in `.env` — per project policy, no numbers are "
        "invented for a provider that was never actually called."
    )

    report = "\n".join(lines)
    print(report)

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\nSaved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
