import requests
import json

BASE_URL = "http://localhost:8001/firewall/check"

# Load test prompts
with open("tests/test_prompts.json", "r") as f:
    test_prompts = json.load(f)

tp = 0  # True Positive  — attack correctly detected
tn = 0  # True Negative  — normal correctly allowed
fp = 0  # False Positive — normal wrongly flagged as attack
fn = 0  # False Negative — attack missed by firewall

print("Running 50 tests...\n")

for i, item in enumerate(test_prompts):
    prompt = item["prompt"]
    expected = item["label"]  # true = attack, false = normal

    response = requests.post(BASE_URL, json={"prompt": prompt})
    result = response.json()
    predicted = result["is_injection"]

    if expected == True and predicted == True:
        tp += 1
        status = "✅ TP"
    elif expected == False and predicted == False:
        tn += 1
        status = "✅ TN"
    elif expected == False and predicted == True:
        fp += 1
        status = "❌ FP"
    else:
        fn += 1
        status = "❌ FN"

    print(f"{i+1}. [{status}] {prompt[:60]}")

# Calculate scores
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print("\n========== RESULTS ==========")
print(f"True Positives  (attacks caught):     {tp}")
print(f"True Negatives  (normal allowed):     {tn}")
print(f"False Positives (normal blocked):     {fp}")
print(f"False Negatives (attacks missed):     {fn}")
print(f"\nPrecision: {precision:.2f}")
print(f"Recall:    {recall:.2f}")
print(f"F1 Score:  {f1:.2f}")
print("==============================")