"""Red herring — deliberately broken Python syntax.

This file has syntax errors that would crash a naive parser. Tree-sitter
recovers and the discovery pipeline must complete without raising. The
file should appear in file_scan_stats but produce zero findings.
"""

def good_function(
    # Unclosed paren — syntax error from here on
    x: int,
    y

class Incomplete(
    # Stray token
    pass !!!
