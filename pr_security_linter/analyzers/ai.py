"""Optional LLM-assisted contextual security reviewer and remediation advisor."""

import os
from typing import Any, Dict, Optional
from ..diff import chunk_diff_smart


class AIReviewProvider:
    """Optional LLM triage provider for pull request diff analysis."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini", timeout: int = 30):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "").strip()
        self.model = model
        self.timeout = timeout

    @property
    def is_available(self) -> bool:
        """Return True only if API key is present and OpenAI package is installed."""
        if not self.api_key:
            return False
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False

    def review_diff(self, diff_text: str) -> str:
        """Send scoped diff context to LLM for advisory review with error handling and fallback."""
        if not self.is_available:
            return "*(AI review skipped: OPENAI_API_KEY not configured or openai package not installed)*"

        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key, timeout=self.timeout)
            optimized_diff = chunk_diff_smart(diff_text, max_chars=12000)

            prompt = (
                "You are an application security reviewer auditing an open-source Pull Request.\n"
                "Analyze the following code diff and provide a concise review:\n"
                "1. [SEVERITY: CRITICAL/HIGH/MEDIUM/LOW] (Include estimated confidence % and risk score).\n"
                "2. Concrete remediation code patches formatted as GitHub suggestions (```suggestion ... ```) when applicable.\n"
                "3. Best practice recommendation.\n"
                "If no vulnerabilities are detected, state: 'No security vulnerabilities detected.'\n\n"
                f"Diff:\n```diff\n{optimized_diff}\n```"
            )

            res = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a concise security code reviewer for pull requests."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
            )
            return res.choices[0].message.content or ""
        except Exception as e:
            return f"*(AI review unavailable due to error: {e})*"
