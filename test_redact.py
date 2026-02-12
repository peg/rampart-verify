#!/usr/bin/env python3
"""Tests for secret redaction."""

from redact import redact_secrets, redact_params


def test_openai_key():
    cmd = 'curl -H "Authorization: Bearer sk-proj-abc123def456ghi789jkl012mno345" https://api.openai.com/v1/chat'
    result = redact_secrets(cmd)
    assert "sk-proj-" not in result
    assert "[REDACTED" in result
    assert "api.openai.com" in result  # URL preserved


def test_github_token():
    cmd = "git clone https://ghp_abcdefghijklmnopqrstuvwxyz1234567890@github.com/user/repo"
    result = redact_secrets(cmd)
    assert "ghp_" not in result
    assert "github.com/user/repo" in result


def test_bearer_header():
    cmd = 'curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.longtoken.signature" https://api.example.com'
    result = redact_secrets(cmd)
    assert "eyJhbG" not in result
    assert "api.example.com" in result


def test_basic_auth_url():
    cmd = "curl https://admin:supersecret123@internal.company.com/api"
    result = redact_secrets(cmd)
    assert "supersecret123" not in result
    assert "admin:" in result  # username preserved
    assert "internal.company.com" in result


def test_aws_key():
    cmd = "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = redact_secrets(cmd)
    assert "wJalrXUtnFEMI" not in result
    assert "AWS_SECRET_ACCESS_KEY" in result  # var name preserved


def test_api_key_env():
    cmd = "API_KEY=abc123secret456 python run_script.py"
    result = redact_secrets(cmd)
    assert "abc123secret456" not in result


def test_no_secrets():
    """Normal commands should pass through unchanged."""
    cmd = "git push origin main"
    assert redact_secrets(cmd) == cmd

    cmd = "docker build -t myapp ."
    assert redact_secrets(cmd) == cmd

    cmd = "ls -la /home/user"
    assert redact_secrets(cmd) == cmd


def test_empty():
    assert redact_secrets("") == ""
    assert redact_secrets(None) is None


def test_redact_params():
    params = {
        "command": 'curl -H "Authorization: Bearer sk-abc123def456ghi789jkl0123" https://api.example.com',
        "timeout": 30,
        "env": {"API_KEY=secret123": "val"},
    }
    result = redact_params(params)
    # Original unchanged
    assert "sk-abc123" in params["command"]
    # Redacted copy
    assert "sk-abc123" not in result["command"]
    assert result["timeout"] == 30


def test_multiple_secrets_one_command():
    cmd = 'curl -H "Authorization: Bearer sk-abc123def456ghi789jkl0123" -H "X-API-Key: ghp_abcdefghijklmnopqrstuvwxyz1234567890" https://api.example.com'
    result = redact_secrets(cmd)
    assert "sk-abc123" not in result
    assert "ghp_" not in result
    assert "api.example.com" in result


def test_password_in_flag():
    cmd = "mysql -u root --password=MyS3cr3tP@ss localhost"
    result = redact_secrets(cmd)
    assert "MyS3cr3tP@ss" not in result


if __name__ == "__main__":
    import sys
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
