"""Red herring — string literal contains the text "subprocess.run".

The new pipeline MUST NOT flag this file as a subprocess-injection risk.
Only real call sites should produce findings; string contents are inside
a (string) node, not a (call) node.
"""


def describe_danger() -> str:
    return "Never invoke subprocess.run with shell=True and untrusted input."
