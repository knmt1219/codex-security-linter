import pytest
from scanner import build_audit_prompt

def test_build_audit_prompt():
    diff_sample = """
    diff --git a/app.py b/app.py
    index 1234567..89abcdef 100644
    --- a/app.py
    +++ b/app.py
    @@ -1,3 +1,3 @@
    -API_KEY = "dummy"
    +API_KEY = "sk-live-1234567890abcdef"
    """
    prompt = build_audit_prompt(diff_sample)
    assert "You are an application security expert" in prompt
    assert "sk-live-1234567890abcdef" in prompt
    assert "Diff:" in prompt
