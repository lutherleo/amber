"""Red herring — commented-out eval() call.

The new pipeline MUST produce no code-injection finding for this file.
Comments are distinct AST node types in tree-sitter, so `(call)` queries
structurally ignore them.
"""


def safe_function(x: int) -> int:
    # The following is intentionally commented out; it is not a real call.
    # result = eval("x + 1")
    return x + 1
