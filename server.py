"""Main FastAPI server for rampart-verify — semantic verification sidecar for Rampart."""

import os
import json
import asyncio
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from providers import get_provider, RECOMMENDED_MODELS
from prompt import create_verification_prompt

# --- Logging setup: console + file ---
LOG_DIR = Path(os.getenv("VERIFY_LOG_DIR", os.path.expanduser("~/.rampart/verify")))
LOG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "verify.log"),
    ],
)
logger = logging.getLogger(__name__)

# Decision log — append-only JSONL for audit.
DECISION_LOG = LOG_DIR / "decisions.jsonl"

# Max request body: 1MB — prevent memory exhaustion from oversized payloads.
MAX_REQUEST_BODY = 1 * 1024 * 1024

app = FastAPI(title="Rampart Verify", description="Semantic verification sidecar for Rampart")


from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    """Reject requests with bodies larger than MAX_REQUEST_BODY."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BODY:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)


def _parse_rate_limit() -> int:
    """Parse requests/minute limit from env with safe fallback."""
    raw = os.getenv("VERIFY_RATE_LIMIT", "60")
    try:
        value = int(raw)
        return value if value > 0 else 60
    except ValueError:
        logger.warning(f"Invalid VERIFY_RATE_LIMIT={raw!r}, using default 60")
        return 60


class TokenBucketRateLimiter:
    """Simple in-memory token bucket rate limiter."""

    def __init__(self, capacity: int, refill_per_second: float):
        self.capacity = float(capacity)
        self.refill_per_second = refill_per_second
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.last_refill = now

            self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_per_second))
            if self.tokens < 1.0:
                return False

            self.tokens -= 1.0
            return True


RATE_LIMIT_PER_MINUTE = _parse_rate_limit()
rate_limiter = TokenBucketRateLimiter(
    capacity=RATE_LIMIT_PER_MINUTE,
    refill_per_second=RATE_LIMIT_PER_MINUTE / 60.0,
)

service_start = time.monotonic()
metrics_lock = asyncio.Lock()
total_requests = 0
total_allows = 0
total_denies = 0
total_errors = 0
total_latency_ms = 0.0
total_latency_samples = 0


async def _record_request_metrics(
    *,
    latency_ms: float,
    decision: Optional[str] = None,
    error: bool = False,
) -> None:
    """Update in-memory metrics counters."""
    global total_allows, total_denies, total_errors, total_latency_ms, total_latency_samples

    async with metrics_lock:
        if decision == "allow":
            total_allows += 1
        elif decision == "deny":
            total_denies += 1
        if error:
            total_errors += 1
        total_latency_ms += latency_ms
        total_latency_samples += 1


class WebhookRequest(BaseModel):
    tool: str
    params: Dict[str, Any]
    agent: Optional[str] = None
    session: Optional[str] = None
    policy: Optional[str] = None
    timestamp: Optional[str] = None
    task_context: Optional[str] = None


class VerificationResponse(BaseModel):
    decision: str  # "allow" or "deny"
    reason: Optional[str] = None
    timestamp: str
    model: str


def log_decision(request: WebhookRequest, response: VerificationResponse, latency_ms: float):
    """Append decision to JSONL audit log."""
    entry = {
        "timestamp": response.timestamp,
        "tool": request.tool,
        "params": request.params,
        "agent": request.agent,
        "session": request.session,
        "task_context": request.task_context,
        "decision": response.decision,
        "reason": response.reason,
        "model": response.model,
        "latency_ms": round(latency_ms, 1),
    }
    try:
        fd = os.open(str(DECISION_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.error(f"Failed to write decision log: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint with provider ping."""
    model = os.getenv("VERIFY_MODEL", "gpt-4o-mini")
    start = time.monotonic()

    try:
        provider = get_provider(model)
        await provider.generate("say ok", max_tokens=5)
        latency_ms = (time.monotonic() - start) * 1000
        status = "healthy"
        error: Optional[str] = None
    except Exception as exc:
        latency_ms = (time.monotonic() - start) * 1000
        status = "degraded"
        error = str(exc)

    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "latency_ms": round(latency_ms, 1),
        "log_dir": str(LOG_DIR),
        **({"error": error} if error else {}),
    }


@app.post("/verify", response_model=VerificationResponse)
async def verify_action(request: WebhookRequest):
    """Main verification endpoint — called by Rampart's action:webhook."""
    global total_requests

    start = time.monotonic()
    model = os.getenv("VERIFY_MODEL", "gpt-4o-mini")

    async with metrics_lock:
        total_requests += 1

    allowed = await rate_limiter.allow()
    if not allowed:
        elapsed = (time.monotonic() - start) * 1000
        await _record_request_metrics(latency_ms=elapsed)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_PER_MINUTE} requests per minute",
        )

    logger.info(f"Verifying {request.tool}: {_summarize_params(request.params)}")

    try:
        provider = get_provider(model)
        prompt = create_verification_prompt(
            request.tool,
            request.params,
            request.task_context,
        )

        raw_response = await provider.generate(prompt)
        decision, reason = parse_llm_response(raw_response)

        result = VerificationResponse(
            decision=decision,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
            model=model,
        )

        elapsed = (time.monotonic() - start) * 1000
        log_decision(request, result, elapsed)
        await _record_request_metrics(latency_ms=elapsed, decision=decision)
        logger.info(f"Decision: {decision} ({elapsed:.0f}ms)" + (f" — {reason}" if reason else ""))
        return result

    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.error(f"Verification failed ({elapsed:.0f}ms): {e}")

        # Fail open — allow on error.
        result = VerificationResponse(
            decision="allow",
            reason=f"Verification unavailable, allowing by default",
            timestamp=datetime.now(timezone.utc).isoformat(),
            model=model,
        )
        log_decision(request, result, elapsed)
        await _record_request_metrics(latency_ms=elapsed, decision="allow", error=True)
        return result


def parse_llm_response(response: str) -> tuple[str, Optional[str]]:
    """Parse LLM response to extract decision and reason."""
    response = response.strip()

    # Handle multi-line responses — take first meaningful line.
    for line in response.split("\n"):
        line = line.strip()
        if not line:
            continue

        upper = line.upper()
        if upper == "ALLOW":
            return "allow", None
        if upper.startswith("DENY"):
            reason = line.split(":", 1)[1].strip() if ":" in line else "Action denied by security review"
            return "deny", reason
        # Some models prefix with "Decision: ALLOW" etc.
        if "ALLOW" in upper and "DENY" not in upper:
            return "allow", None
        if "DENY" in upper:
            reason = line.split(":", 1)[1].strip() if ":" in line else "Action denied by security review"
            return "deny", reason

    # Unclear response — fail open.
    logger.warning(f"Unclear LLM response, allowing: {response[:100]}")
    return "allow", None


def _summarize_params(params: dict) -> str:
    """Short summary of params for logging (no secrets)."""
    if "command" in params:
        cmd = str(params["command"])
        return cmd[:80] + ("..." if len(cmd) > 80 else "")
    if "path" in params or "file_path" in params:
        return str(params.get("path", params.get("file_path", "")))[:80]
    if "url" in params:
        return str(params["url"])[:80]
    return str(params)[:80]


@app.get("/")
async def root():
    """Root endpoint with service info."""
    model = os.getenv("VERIFY_MODEL", "gpt-4o-mini")
    return {
        "service": "rampart-verify",
        "version": "0.1.0",
        "model": model,
        "recommended_models": RECOMMENDED_MODELS,
    }


@app.get("/metrics")
async def metrics():
    """Simple in-process metrics endpoint."""
    now = time.monotonic()
    async with metrics_lock:
        avg_latency_ms = (total_latency_ms / total_latency_samples) if total_latency_samples else 0.0
        return {
            "total_requests": total_requests,
            "total_allows": total_allows,
            "total_denies": total_denies,
            "total_errors": total_errors,
            "avg_latency_ms": round(avg_latency_ms, 1),
            "model": os.getenv("VERIFY_MODEL", "gpt-4o-mini"),
            "uptime_seconds": round(now - service_start, 1),
        }


def main():
    """Main entry point."""
    port = int(os.getenv("VERIFY_PORT", "8090"))
    host = os.getenv("VERIFY_HOST", "127.0.0.1")

    logger.info(f"Starting rampart-verify on {host}:{port}")
    logger.info(f"Model: {os.getenv('VERIFY_MODEL', 'gpt-4o-mini')}")
    logger.info(f"Decision log: {DECISION_LOG}")

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
