from fastapi import APIRouter
from pydantic import BaseModel, Field
import numpy as np

router = APIRouter()

# Suspicious keywords that indicate instruction-like language
POISON_KEYWORDS = [
    "ignore", "always", "never", "you must", "forget",
    "override", "disregard", "from now on", "your new instructions",
    "do not follow", "bypass", "pretend", "act as if",
    "your previous instructions", "you are now"
]

# In-memory store to simulate existing memories
memory_store = [
    "The weather in Mumbai is hot today.",
    "Python is a popular programming language.",
    "The user prefers dark mode.",
    "Last login was from Mumbai.",
    "The project deadline is next Friday."
]

class MemoryRequest(BaseModel):
    content: str = Field(..., max_length=10_000)
    agent_id: str = Field(..., max_length=200)

def check_keywords(content: str) -> tuple[bool, str]:
    content_lower = content.lower()
    for keyword in POISON_KEYWORDS:
        if keyword in content_lower:
            return True, f"Contains suspicious keyword: '{keyword}'"
    return False, "No suspicious keywords found"

def get_simple_embedding(text: str) -> np.ndarray:
    # Simple character frequency embedding for demo
    text = text.lower()
    vector = np.zeros(26)
    for char in text:
        if char.isalpha():
            vector[ord(char) - ord('a')] += 1
    norm = np.linalg.norm(vector)
    if norm > 0:
        vector = vector / norm
    return vector

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))

def check_outlier(content: str) -> tuple[bool, str]:
    if len(memory_store) == 0:
        return False, "No existing memories to compare"
    
    new_embedding = get_simple_embedding(content)
    similarities = []
    
    for memory in memory_store:
        existing_embedding = get_simple_embedding(memory)
        sim = cosine_similarity(new_embedding, existing_embedding)
        similarities.append(sim)
    
    avg_similarity = np.mean(similarities)
    
    if avg_similarity < 0.3:
        return True, f"Memory is an outlier (avg similarity: {avg_similarity:.2f})"
    return False, f"Memory fits normal pattern (avg similarity: {avg_similarity:.2f})"

def assess_poison(content: str) -> dict:
    """Pure function version of the poison check, reusable by both the HTTP endpoint and the
    memory-write pipeline (Batch 5) without a self-referential HTTP call."""
    reasons = []
    is_poisoned = False

    keyword_flag, keyword_reason = check_keywords(content)
    if keyword_flag:
        is_poisoned = True
        reasons.append(keyword_reason)

    outlier_flag, outlier_reason = check_outlier(content)
    if outlier_flag:
        is_poisoned = True
        reasons.append(outlier_reason)

    confidence = min(1.0, len(reasons) * 0.5)

    return {
        "is_poisoned": is_poisoned,
        "reason": "; ".join(reasons) if reasons else "Memory appears clean",
        "confidence": confidence,
    }


def memory_risk_score(injection_confidence: float = 0.0, poison_confidence: float = 0.0, has_pii: bool = False) -> float:
    """Phase 6 — combines injection probability, poison probability, and PII presence into a
    single 0.0-1.0 risk score used by the policy engine's QUARANTINE threshold."""
    pii_component = 0.3 if has_pii else 0.0
    score = (0.5 * injection_confidence) + (0.4 * poison_confidence) + pii_component
    return round(min(1.0, score), 4)


@router.post("/firewall/check-memory")
def check_memory(request: MemoryRequest):
    return assess_poison(request.content)