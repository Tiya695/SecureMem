from fastapi import APIRouter
from pydantic import BaseModel
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
    content: str
    agent_id: str

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

@router.post("/firewall/check-memory")
def check_memory(request: MemoryRequest):
    reasons = []
    is_poisoned = False

    # Check 1 — keyword check
    keyword_flag, keyword_reason = check_keywords(request.content)
    if keyword_flag:
        is_poisoned = True
        reasons.append(keyword_reason)

    # Check 2 — outlier check
    outlier_flag, outlier_reason = check_outlier(request.content)
    if outlier_flag:
        is_poisoned = True
        reasons.append(outlier_reason)

    confidence = min(1.0, len(reasons) * 0.5)

    return {
        "is_poisoned": is_poisoned,
        "reason": "; ".join(reasons) if reasons else "Memory appears clean",
        "confidence": confidence
    }