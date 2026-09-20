"""Red herring — mentions postgres-shaped keywords in a docstring.

This mirrors the `gpg.ssh.allowedSignersFile` case from the old pipeline.
Contains no actual database code; the only occurrence of "postgres" is
inside this docstring. The new pipeline MUST produce zero findings for
this file, because tree-sitter queries over AST nodes structurally ignore
comments and docstrings.

    Note: SSH-signed commits require gpg.ssh.allowedSignersFile to be
    configured. See the documentation for pg_config (not related).
"""


def check_signers_file() -> bool:
    # The word "postgres" does not appear outside the docstring above.
    return True
