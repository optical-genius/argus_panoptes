"""
Argus Panoptes - Local ML / DLP Proxy Service (FastAPI)
Acts as a proxy for LM Studio, Ollama, and Cloud LLMs.
"""

import os
import re
import time
import httpx
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from recognizers.hetu_recognizer import find_finnish_hetus
from recognizers.entropy_scanner import find_high_entropy_tokens

app = FastAPI(title="Argus Panoptes DLP Guardrail Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_BASE_URL = os.environ.get("ARGUS_TARGET_BASE_URL", "http://127.0.0.1:1234/v1")
GUARD_MODE = os.environ.get("ARGUS_MODE", "mask") # mask | block | audit_only

# Session Token Vault
class TokenVault:
    def __init__(self):
        self.placeholder_to_original: Dict[str, str] = {}
        self.original_to_placeholder: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}

    def get_token(self, original: str, category: str) -> str:
        if original in self.original_to_placeholder:
            return self.original_to_placeholder[original]
        count = self.counters.get(category, 0) + 1
        self.counters[category] = count
        token = f"<ARGUS_{category}_{count}>"
        self.placeholder_to_original[token] = original
        self.original_to_placeholder[original] = token
        return token

    def unmask(self, text: str) -> str:
        for placeholder, original in self.placeholder_to_original.items():
            text = text.replace(placeholder, original)
        return text

vault = TokenVault()

SECRET_PATTERNS = [
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{32,80}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{40,100}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b")),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("DATABASE_URL", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s:@]+:[^\s:@]+@[^\s:@]+\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]

def scan_text(text: str) -> Dict[str, Any]:
    start = time.perf_counter()
    violations = []

    # 1. Regex Secrets
    for cat, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            violations.append({
                "category": cat,
                "text": m.group(0),
                "start": m.start(),
                "end": m.end()
            })

    # 2. Finnish HETU
    for item in find_finnish_hetus(text):
        violations.append({
            "category": "FINNISH_HETU",
            "text": item["hetu"],
            "start": item["start"],
            "end": item["end"]
        })

    # 3. High Entropy
    for item in find_high_entropy_tokens(text):
        violations.append({
            "category": "HIGH_ENTROPY",
            "text": item["token"],
            "start": item["start"],
            "end": item["end"]
        })

    # Deduplicate & sort
    violations.sort(key=lambda x: x["start"], reverse=True)
    clean_violations = []
    last_end = 999999999
    for v in violations:
        if v["end"] <= last_end:
            clean_violations.append(v)
            last_end = v["start"]

    # Mask text
    sanitized = text
    for v in clean_violations:
        token = vault.get_token(v["text"], v["category"])
        sanitized = sanitized[:v["start"]] + token + sanitized[v["end"]:]

    duration = round((time.perf_counter() - start) * 1000, 2)
    return {
        "has_violations": len(clean_violations) > 0,
        "total": len(clean_violations),
        "violations": clean_violations,
        "sanitized_text": sanitized,
        "duration_ms": duration
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "Argus Panoptes Python Backend",
        "target": TARGET_BASE_URL,
        "mode": GUARD_MODE
    }

class ScanRequest(BaseModel):
    text: str

@app.post("/api/scan")
def api_scan(req: ScanRequest):
    return scan_text(req.text)

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    messages = body.get("messages", [])
    combined = "\n".join(m.get("content", "") for m in messages if isinstance(m.get("content"), str))

    scan_res = scan_text(combined)

    if scan_res["has_violations"]:
        if GUARD_MODE == "block":
            raise HTTPException(
                status_code=403,
                detail=f"🛡️ [Argus Panoptes] Blocked! Detected sensitive data: {len(scan_res['violations'])} item(s)."
            )
        elif GUARD_MODE == "mask":
            # Mask messages
            for m in messages:
                if isinstance(m.get("content"), str):
                    m["content"] = scan_text(m["content"])["sanitized_text"]
            body["messages"] = messages

    # Forward to target LLM (LM Studio / Ollama)
    target_url = f"{TARGET_BASE_URL.rstrip('/')}/chat/completions"
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(
                target_url,
                json=body,
                headers={"Authorization": request.headers.get("authorization", "Bearer dummy")}
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to reach target LLM: {str(e)}")

        resp_text = resp.text
        if GUARD_MODE == "mask":
            resp_text = vault.unmask(resp_text)

        return Response(
            content=resp_text,
            status_code=resp.status_code,
            media_type="application/json"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8081)

