from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from typing import Any

from .config import Config, Defaults, Drivers, Paths, Target
from .m8 import write_composite_config, write_qualification_config
from .policy import write_policy
from .util import atomic_json


EXAMPLE_FILES = (
    Path("sk-live-policy.json"),
    Path("m8-composite-config.json"),
    Path("m8-external/m8-policy-hardware.json"),
    Path("m8-external/m8-policy-int3.json"),
    Path("m8-external/m8-qualification.json"),
)


def _example_bench(root: Path) -> tuple[Config, Target]:
    """Create disposable filesystem inputs accepted by the production M8 writers."""
    tools = root / "tools"
    symbols = root / "symbols"
    profile = root / "profiles" / "vmwp-dispatcher-profile.json"
    secure_kernel = root / "artifacts" / "securekernel.exe"
    for path in (
        tools / "windbg.exe",
        tools / "DbgX.Shell.exe",
        tools / "cdb.exe",
        profile,
        secure_kernel,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    symbols.mkdir()

    paths = Paths(
        windbg_mcp_repo=root / "windbg-mcp",
        windbg_mcp_exe=root / "windbg-mcp" / "windbg-mcp.exe",
        debugger_exe=tools / "windbg.exe",
        classic_debugger_exe=tools / "windbg.exe",
        windbgx_exe=tools / "DbgX.Shell.exe",
        symbol_path=symbols,
        cdb_exe=tools / "cdb.exe",
        windows_kit_root=root / "Windows Kits" / "10",
        artifacts_root=root / "artifacts",
        runs_root=root / "runs",
        state_root=root / ".state",
    )
    target = Target(
        name="example",
        vm_id="00000000-0000-0000-0000-000000000000",
        vm_name="Disposable Secure Kernel example VM",
        disposable=True,
        profile=profile,
        secure_kernel_image=secure_kernel,
        guest_spin_host=r"C:\encl\spin_host.exe",
        guest_enclave_image=r"C:\encl\spin_enclave.dll",
    )
    config = Config(
        source=root / "config.local.toml",
        paths=paths,
        defaults=Defaults(),
        targets={target.name: target},
        drivers=Drivers(),
    )
    return config, target


def _portable(value: Any, *, generated_root: Path) -> Any:
    """Replace machine-local roots in generated JSON with documented placeholders."""
    if isinstance(value, str):
        repository = Path(__file__).resolve().parents[2]
        replacements = (
            (sys.executable, "${PYTHON}"),
            (str(generated_root), "${SKLAB_ROOT}"),
            (str(repository), "${SKLAB_REPO}"),
        )
        for before, after in replacements:
            value = value.replace(before, after)
        if any(
            placeholder in value
            for placeholder in ("${PYTHON}", "${SKLAB_ROOT}", "${SKLAB_REPO}")
        ):
            value = value.replace("\\", "/")
        return value
    if isinstance(value, dict):
        return {
            str(key): _portable(item, generated_root=generated_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_portable(item, generated_root=generated_root) for item in value]
    return value


def generate(destination: Path) -> tuple[Path, ...]:
    """Regenerate sanitized, non-runnable examples with the production M8 writers."""
    destination = destination.resolve(strict=False)
    with tempfile.TemporaryDirectory() as directory:
        generated_root = Path(directory).resolve()
        config, target = _example_bench(generated_root)
        raw = generated_root / "generated"
        write_policy(config, target, raw / EXAMPLE_FILES[0])
        write_composite_config(config, target, raw / EXAMPLE_FILES[1])
        write_qualification_config(config, target, raw / "m8-external")

        written = []
        for relative in EXAMPLE_FILES:
            value = json.loads((raw / relative).read_text(encoding="utf-8"))
            output = destination / relative
            atomic_json(output, _portable(value, generated_root=generated_root))
            written.append(output)
    return tuple(written)
