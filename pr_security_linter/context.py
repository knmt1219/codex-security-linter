"""Context-aware source code filtering, comment parsing, and secret value masking."""

from .patterns import (
    is_comment_line,
    is_ignored_file,
    mask_sensitive_value,
    strip_inline_comment,
)

__all__ = [
    "is_comment_line",
    "strip_inline_comment",
    "is_ignored_file",
    "mask_sensitive_value",
]
