from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import threading
from typing import Any

from .config import Config, Target
from .errors import ExecutionFailure, PrerequisiteError
from .manifest import RunManifest
from .output import Output


@dataclass
class RunContext:
    config: Config
    output: Output
    manifest: RunManifest
    target: Target | None
    assume_yes: bool = False
    cancel_event: threading.Event | None = None

    @property
    def run_dir(self) -> Path:
        return self.manifest.directory

    def require_disposable(self) -> None:
        if self.target is None or not self.target.disposable:
            raise PrerequisiteError("this module requires a target with disposable = true")

    def cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()

    def confirm(self, prompt: str) -> None:
        if self.assume_yes:
            return
        if not os.isatty(0):
            raise PrerequisiteError("mutation requires --yes when stdin is not interactive")
        answer = input(f"{prompt} [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            raise PrerequisiteError("operator declined the mutation")

    def run_process(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float | None = None,
        name: str = "process",
    ) -> subprocess.CompletedProcess[str]:
        self.output.event("phase", f"starting {name}", command=subprocess.list2cmdline(command))
        merged = os.environ.copy()
        if env:
            merged.update(env)
        completed = subprocess.run(
            command,
            cwd=cwd or self.config.paths.windbg_mcp_repo,
            env=merged,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        (self.run_dir / f"{name}.stdout.log").write_text(completed.stdout, encoding="utf-8")
        (self.run_dir / f"{name}.stderr.log").write_text(completed.stderr, encoding="utf-8")
        if completed.stdout:
            print(completed.stdout, end="", file=self.output.stream)
        if completed.stderr:
            print(completed.stderr, end="", file=self.output.stream)
        self.manifest.add_event(name, command=command, exit_code=completed.returncode)
        if completed.returncode:
            raise ExecutionFailure(f"{name} exited {completed.returncode}")
        return completed

