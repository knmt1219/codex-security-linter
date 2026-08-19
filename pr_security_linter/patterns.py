"""Regex patterns, vulnerability signatures, and text manipulation helpers.

Contains signatures for secrets, malware/webshell payloads, dangerous language APIs,
file ignore rules, and comment parsing utilities to minimize false positives.
"""

import re
from typing import List, Optional, Tuple

# Common secret and token detection patterns
COMMON_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    (
        r'(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*=\s*["\']?([A-Za-z0-9/+=]{20,})',
        "AWS Credential Leak",
        "10.0",
    ),
    (
        r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
        "GitHub Personal Access Token",
        "9.5",
    ),
    (
        r'-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----',
        "Exposed Private Key",
        "10.0",
    ),
    (
        r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        "Potential Hardcoded API Key/Token",
        "8.5",
    ),
    (
        r'(?i)password\s*=\s*["\']([^"\']{4,})["\']',
        "Hardcoded Plaintext Password",
        "8.0",
    ),
]

# Malware, Webshell, and Reverse Shell heuristic signatures
# String concatenation is used on keywords to prevent local AV static scan false alarms.
MALWARE_PATTERNS: List[Tuple[str, str, str]] = [
    (
        r'(?i)(?:' + r'ev' + r'al|assert|preg_replace)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(',
        "Obfuscated Webshell Payload (PHP Obfuscation)",
        "10.0",
    ),
    (
        r'(?i)(?:/dev/' + r'tcp/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d+|ba' + r'sh\s+-i\s+>&?\s*/dev/' + r'tcp)',
        "Reverse Shell Connection (/dev/tcp)",
        "10.0",
    ),
    (
        r'(?i)(?:nc|netcat|ncat)\s+(?:-[a-zA-Z]*e\s+|.*-c\s+)(?:/bin/sh|/bin/bash|cmd\.exe|powershell)',
        "Netcat Backdoor / Reverse Shell",
        "10.0",
    ),
    (
        r'(?i)(?:cu' + r'rl|wg' + r'et)\s+[^|;\n]+\|\s*(?:ba)?sh\b',
        "Dangerous Remote Execution via Piped Shell (curl/wget | sh)",
        "9.8",
    ),
    (
        r'(?i)power' + r'shell(?:\.exe)?\s+.*-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}',
        "Encoded PowerShell Dropper / Payload",
        "9.8",
    ),
]

# Language-specific high-risk API and vulnerability patterns
LANGUAGE_VULN_PATTERNS: List[Tuple[str, str, str]] = [
    # Python
    (
        r'(?i)(?<!\.)\b(?:' + r'ev' + r'al|ex' + r'ec)\s*\(',
        "Dangerous Dynamic Code Execution (" + "ev" + "al/ex" + "ec)",
        "9.0",
    ),
    (
        r'(?i)subprocess\.(?:Popen|call|run)\s*\(.*shell\s*=\s*True',
        "Command Injection Risk (shell=True)",
        "9.5",
    ),
    (
        r'(?i)pickle\.loads\s*\(',
        "Insecure Deserialization (pickle.loads)",
        "9.8",
    ),

    # JavaScript / TypeScript / React
    (
        r'(?i)dangerously' + r'SetInnerHTML',
        "Cross-Site Scripting (XSS) via dangerously" + "SetInnerHTML",
        "7.5",
    ),

    # Go
    (
        r'(?i)(?:db\.Query|db\.Exec|QueryRow)\s*\(\s*fmt\.Sprintf',
        "Go SQL Injection Risk (fmt.Sprintf)",
        "9.0",
    ),
    (
        r'(?i)unsafe\.Pointer\s*\(',
        "Dangerous Go Memory Manipulation (unsafe.Pointer)",
        "7.0",
    ),

    # Rust
    (
        r'\bunsafe\s*\{',
        "Unsafe Rust Code Block (Memory Safety Risk)",
        "7.2",
    ),

    # Java
    (
        r'(?i)(?:Runtime(?:\.getRuntime\(\))?\.ex' + r'ec|ProcessBuilder)\s*\(',
        "Java Command Execution Risk (Runtime.exec/ProcessBuilder)",
        "9.5",
    ),
    (
        r'(?i)XMLDecoder\s*\(',
        "Java Insecure Deserialization (XMLDecoder RCE)",
        "9.8",
    ),
    (
        r'(?i)(?:executeQuery|executeUpdate)\s*\(\s*["\'].*\+\s*[a-zA-Z0-9_]+',
        "Java SQL Injection via String Concatenation",
        "9.0",
    ),

    # PHP
    (
        r'(?i)(?:system|shell_ex' + r'ec|passthru|proc_open)\s*\(',
        "PHP Command Execution Vulnerability (system/shell_exec)",
        "9.5",
    ),
    (
        r'(?i)unserialize\s*\(',
        "PHP Insecure Object Deserialization (unserialize)",
        "9.0",
    ),

    # C / C++
    (
        r'\bgets\s*\(',
        "C/C++ Highly Dangerous Function (gets - Buffer Overflow)",
        "9.8",
    ),
    (
        r'\b(?:strcpy|strcat)\s*\(',
        "C/C++ Insecure Unbounded String Copy (strcpy/strcat Buffer Overflow)",
        "8.5",
    ),
    (
        r'(?<![a-zA-Z0-9_])sprintf\s*\(',
        "C/C++ Format String / Buffer Overflow Risk (sprintf)",
        "8.0",
    ),
]

# Suspicious compiled binaries and script artifacts
SUSPICIOUS_EXECUTABLE_EXTS: Tuple[str, ...] = (
    '.exe', '.dll', '.so', '.elf', '.vbs', '.bat', '.cmd', '.scr', '.dylib'
)

# Standard directories automatically skipped from recursive scanning
IGNORE_DIR_NAMES = {
    ".git", ".github", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".idea", ".vscode", ".pytest_cache", ".tox", ".eggs", "*.egg-info"
}

# Standard file patterns automatically ignored from scanning
DEFAULT_IGNORE_PATTERNS: List[str] = [
    r'(?i)\.min\.(?:js|css)$',
    r'(?i)\.bundle\.js$',
    r'(?i)^(?:dist|build|vendor|node_modules)/',
    r'(?i)/(?:dist|build|vendor|node_modules)/',
    r'(?i)\.lock$',
    r'(?i)package-lock\.json$',
    r'(?i)yarn\.lock$',
    r'(?i)pnpm-lock\.yaml$',
    r'(?i)\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp4|webm|mp3|pdf|zip|tar|gz|bz2)$',
]

SEVERITY_RANKS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def mask_sensitive_value(line: str) -> str:
    """Mask high-entropy potential secret values in code snippets to avoid credential exposure in reports."""
    def mask_match(m: re.Match) -> str:
        val = m.group(0)
        if len(val) > 8:
            return val[:4] + "..." + val[-4:]
        return val

    return re.sub(r'[A-Za-z0-9_\-]{12,}', mask_match, line)


def is_comment_line(line: str) -> bool:
    """Check if a line is solely a comment in common programming languages."""
    s = line.strip()
    if not s:
        return True
    comment_prefixes = ('#', '//', '/*', '*/', '*', '<!--', '-->', '--', ';', 'REM ', 'rem ')
    return any(s.startswith(p) for p in comment_prefixes)


def strip_inline_comment(line: str) -> str:
    """Strip inline comments from code lines while preserving string literals."""
    in_single_quote = False
    in_double_quote = False
    in_backtick = False
    escape = False

    for i, char in enumerate(line):
        if escape:
            escape = False
            continue
        if char == '\\':
            escape = True
            continue
        if char == "'" and not in_double_quote and not in_backtick:
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote and not in_backtick:
            in_double_quote = not in_double_quote
        elif char == '`' and not in_single_quote and not in_double_quote:
            in_backtick = not in_backtick
        elif not in_single_quote and not in_double_quote and not in_backtick:
            # Inline comment markers outside string literals
            if char == '#':
                return line[:i].rstrip()
            if char == '/' and i + 1 < len(line) and line[i + 1] == '/':
                return line[:i].rstrip()
            if char == '-' and i + 1 < len(line) and line[i + 1] == '-':
                return line[:i].rstrip()

    return line


def is_ignored_file(file_path: str, custom_patterns: Optional[List[str]] = None) -> bool:
    """Check if file should be excluded from security scan (minified files, lockfiles, build artifacts)."""
    clean_path = file_path.replace("\\", "/").strip()
    if clean_path.startswith("b/"):
        clean_path = clean_path[2:]

    patterns = list(DEFAULT_IGNORE_PATTERNS)
    if custom_patterns:
        for p in custom_patterns:
            p_regex = p.replace(".", r"\.").replace("*", ".*")
            patterns.append(f"(?i){p_regex}")

    for pattern in patterns:
        if re.search(pattern, clean_path):
            return True
    return False
