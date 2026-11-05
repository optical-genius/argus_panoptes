"""
Shannon Entropy calculation and scanner for random secrets/passwords in Python.
"""

import math
import re

def calculate_shannon_entropy(token: str) -> float:
    if not token:
        return 0.0

    length = len(token)
    counts = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def find_high_entropy_tokens(text: str, min_length: int = 20, threshold: float = 4.2):
    token_regex = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
    results = []

    for match in token_regex.finditer(text):
        token = match.group(0)
        if len(token) >= min_length:
            ent = calculate_shannon_entropy(token)
            if ent >= threshold:
                results.append({
                    "token": token,
                    "entropy": round(ent, 2),
                    "start": match.start(),
                    "end": match.end()
                })

    return results

