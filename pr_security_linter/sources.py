"""Source input abstractions, diff parsing, and source code discovery."""

from .diff import chunk_diff_smart, count_scanned_lines

__all__ = ["chunk_diff_smart", "count_scanned_lines"]
