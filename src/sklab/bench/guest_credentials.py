from __future__ import annotations

import os
from pathlib import Path


def powershell_credential() -> str:
    """Build a PowerShell prefix that reads a local, ignored credential JSON file."""
    configured = os.environ.get("SKLAB_GUEST_CREDENTIAL_FILE", "")
    path = Path(configured).expanduser().resolve(strict=False) if configured else None
    if path is None or not path.is_file():
        raise RuntimeError(
            "guest workflow requires targets.<name>.guest_credential_file; "
            "the JSON file must contain username and password"
        )
    escaped = str(path).replace("'", "''")
    return (
        f"$g=Get-Content -LiteralPath '{escaped}' -Raw | ConvertFrom-Json;"
        "$c=New-Object System.Management.Automation.PSCredential([string]$g.username,"
        "(ConvertTo-SecureString ([string]$g.password) -AsPlainText -Force));"
    )
