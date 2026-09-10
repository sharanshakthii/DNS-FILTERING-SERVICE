"""
Generate a password hash for `DNSF_AUTH_PASSWORD_HASH`.

The password is read from a prompt, never from a command-line argument. An
argument would land in shell history, in the process list while the command
runs, and in any terminal recording — which is how development credentials
usually leak.

Nothing is written to disk. The hash is printed for you to place in your own
environment configuration; the plaintext is never stored anywhere by this
project.

Usage:
    python tools/make_password_hash.py

Then, in the terminal that runs the API:

    PowerShell:  $env:DNSF_AUTH_USERNAME="admin"
                 $env:DNSF_AUTH_PASSWORD_HASH="pbkdf2_sha256$..."
    bash:        export DNSF_AUTH_USERNAME=admin
                 export DNSF_AUTH_PASSWORD_HASH='pbkdf2_sha256$...'

In PowerShell the hash must be in double quotes; in bash use single quotes,
because the `$` separators would otherwise be expanded as variables.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from api.auth import ITERATIONS, hash_password  # noqa: E402

MINIMUM_LENGTH = 8


def main() -> int:
    print("Generate a password hash for the PRJ_112 web console.")
    # Read from api.auth rather than restated here, so the printed
    # figure cannot drift away from the value actually used.
    print(f"PBKDF2-HMAC-SHA256, {ITERATIONS:,} iterations, "
          f"random per-password salt.\n")

    try:
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm : ")
    except (KeyboardInterrupt, EOFError):
        print("\ncancelled")
        return 1

    if password != confirmation:
        print("\nThe two entries do not match.", file=sys.stderr)
        return 1
    if len(password) < MINIMUM_LENGTH:
        print(f"\nUse at least {MINIMUM_LENGTH} characters.", file=sys.stderr)
        return 1

    digest = hash_password(password)

    print("\nSet these in the terminal that runs the API:\n")
    print("  PowerShell")
    print('    $env:DNSF_AUTH_USERNAME="admin"')
    print(f'    $env:DNSF_AUTH_PASSWORD_HASH="{digest}"')
    print("\n  bash / zsh")
    print("    export DNSF_AUTH_USERNAME=admin")
    print(f"    export DNSF_AUTH_PASSWORD_HASH='{digest}'")
    print("\nThe hash is safe to keep in your own environment configuration. "
          "Do not commit it, and do not commit the password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
