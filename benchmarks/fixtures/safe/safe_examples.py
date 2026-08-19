"""Safe coding patterns, documentation, comments, and standard library helpers.

These examples MUST NOT trigger any security findings or false positives.
"""

import ast
import subprocess

# TODO: never use eval() in production
# Subprocess with shell=True is dangerous, so use list instead:
# Example: pickle.loads is unsafe for network RPC

def safe_parser(data_str):
    # ast.literal_eval is safe for parsing string literals
    return ast.literal_eval(data_str)

def safe_command_runner(target_file):
    # shell=False (default) with parameter list is safe
    return subprocess.run(["git", "status", target_file], check=True)

class DocumentationExample:
    """This docstring mentions eval and exec without calling them."""
    pass
