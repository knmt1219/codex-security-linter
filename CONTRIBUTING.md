# Contributing to PR Security Linter

Thank you for your interest in contributing to **PR Security Linter**! We welcome contributions that improve vulnerability detection accuracy, eliminate false positives, enhance performance, or improve reporting formats.

---

## Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/pr-security-linter.git
   cd pr-security-linter
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
   ```

3. **Install the package in editable mode with development dependencies:**
   ```bash
   pip install -e .[dev,ai]
   ```

---

## Running Tests

We use `pytest` for automated unit testing:

```bash
python -m pytest tests/ -v
```

Before submitting a pull request, ensure all tests pass cleanly.

---

## Guidelines for Heuristic & Rule Contributions

- **Low False Positives First**: A security linter that produces too much noise will be ignored by developers. Ensure regex patterns are targeted and take code context (e.g. comments, docstrings) into account.
- **Explain the Threat Model**: When adding a new pattern, provide clear descriptions and references explaining why the pattern poses a security risk.
- **Add Test Cases**: Every new or modified rule must include unit test cases in `tests/test_scanner.py` covering both positive hits and negative/safe cases.
- **Maintain Performance**: PR Security Linter is designed to be fast and lightweight. Avoid expensive operations in the hot parsing path.

---

## Submitting Pull Requests

1. Create a feature branch (`git checkout -b feature/my-feature`).
2. Make your changes with clear, descriptive commit messages.
3. Run the test suite and verify 100% pass rate.
4. Push your branch to GitHub and open a Pull Request.

---

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
