"""Backward compatibility wrapper for codex_security_linter.scanner."""

from pr_security_linter.scanner import *
from pr_security_linter.scanner import main

if __name__ == "__main__":
    main()
