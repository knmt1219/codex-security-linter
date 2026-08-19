#!/usr/bin/env python3
"""PR Security Linter - Standalone CLI execution entrypoint.

Fast, lightweight security linter & secret scanner for Git pull requests and local code repositories.
"""

from pr_security_linter.scanner import (
    main,
    heuristic_scan_structured,
    scan_local_path_offline,
    count_scanned_lines,
    chunk_diff_smart,
    load_config,
    install_pre_commit_hook,
    should_fail_on_severity,
    write_github_action_outputs,
    parse_simple_yaml,
)
from pr_security_linter.patterns import (
    COMMON_SECRET_PATTERNS,
    MALWARE_PATTERNS,
    LANGUAGE_VULN_PATTERNS,
    SUSPICIOUS_EXECUTABLE_EXTS,
    mask_sensitive_value,
    is_ignored_file,
    is_comment_line,
    strip_inline_comment,
)
from pr_security_linter.reporters import (
    build_markdown_summary_table,
    generate_svg_badge,
    export_sarif,
    export_html,
    export_json,
)
from pr_security_linter import __version__

VERSION = __version__

if __name__ == "__main__":
    main()
