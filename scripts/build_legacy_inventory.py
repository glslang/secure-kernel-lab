from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "legacy"


def main() -> None:
    rows = []
    for path in sorted(LEGACY.rglob("*")):
        if not path.is_file() or path.name in {"inventory.json", "README.md"}:
            continue
        rows.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest().upper(),
            }
        )
    (LEGACY / "inventory.json").write_text(
        json.dumps({"schema": "secure-kernel-lab.legacy-inventory.v1", "files": rows}, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
