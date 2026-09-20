# Fixture: red_herrings

Files that demonstrate the exact false-positive patterns that broke the old
regex-based pipeline. Every file in this directory MUST produce zero findings
from the new tree-sitter pipeline. These are the SC-001 regression tests.

Contents:
- `docstring_postgres.py` — docstring mentions `gpg.ssh.allowedSignersFile`
  (the `pg\.` regex of the old pipeline matched this incorrectly)
- `metadata_email.py` — config-metadata parser with `email=data.get("email", "")`
  (the old pipeline flagged this as PII handling)
- `commented_eval.py` — commented-out `eval("...")` call (structurally a comment,
  not a call, so tree-sitter queries must ignore it)
- `string_subprocess.py` — docstring literal contains the text `"subprocess.run"`
  but no actual call (the old regex would match anywhere in the file)
