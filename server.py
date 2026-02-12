"""Main FastAPI server for rampart-verify — semantic verification sidecar for Rampart."""

import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

from providers import get_provider, RECOMMENDED_MODELS
from prompt import create_verification_prompt

# --- Logging setup: console + file ---
LOG_DIR = Path(os.getenv("VERIFY_LOG_DIR", os.path.expanduser("~/.rampart/verify")))
LOG_DIR.mkdir(parents=True, exist_ok=True)

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

app = FastAPI(title="Rampart Verify", description="Semantic verification sidecar for Rampart")


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
        with open(DECISION_LOG, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.error(f"Failed to write decision log: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    model = os.getenv("VERIFY_MODEL", "gpt-4o-mini")
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "log_dir": str(LOG_DIR),
    }


@app.post("/verify", response_model=VerificationResponse)
async def verify_action(request: WebhookRequest):
    """Main verification endpoint — called by Rampart's action:webhook."""
    import time

    start = time.monotonic()
    model = os.getenv("VERIFY_MODEL", "gpt-4o-mini")

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
