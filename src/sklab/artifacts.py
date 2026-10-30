from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from .errors import PrerequisiteError
from .util import sha256


@dataclass(frozen=True)
class Artifact:
    name: str
    path: Path
    sha256: str
    required_by: tuple[str, ...]
    description: str


def load_manifest(path: Path, artifacts_root: Path) -> dict[str, Artifact]:
    if not path.is_file():
        return {}
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    result: dict[str, Artifact] = {}
    for name, row in raw.get("artifacts", {}).items():
        item = Path(str(row["path"]))
        if not item.is_absolute():
            item = artifacts_root / item
        result[name] = Artifact(
            name=name,
            path=item.resolve(strict=False),
            sha256=str(row["sha256"]).upper(),
            required_by=tuple(str(value) for value in row.get("required_by", [])),
            description=str(row.get("description", "")),
        )
    return result


def verify(artifact: Artifact) -> dict[str, object]:
    if not artifact.path.is_file():
        return {"name": artifact.name, "status": "missing", "path": str(artifact.path)}
    actual = sha256(artifact.path)
    return {
        "name": artifact.name,
        "status": "ok" if actual == artifact.sha256 else "hash_mismatch",
        "path": str(artifact.path),
        "expected_sha256": artifact.sha256,
        "actual_sha256": actual,
        "bytes": artifact.path.stat().st_size,
    }


def require(artifact: Artifact) -> None:
    result = verify(artifact)
    if result["status"] != "ok":
        raise PrerequisiteError(f"artifact {artifact.name} failed verification: {result}")

