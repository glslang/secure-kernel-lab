from __future__ import annotations

import cmd
from dataclasses import dataclass, field
import json
from pathlib import Path
import shlex
import threading
from typing import Any

from .cli import module_rows, render_banner, resolve_module, run_driver, run_vm
from .config import Config
from .doctor import passed
from .errors import LabError
from .modules.spec import ModuleSpec
from .output import Output
from .runner import RunOutcome, check_module, execute_module
from .util import parse_scalar


@dataclass
class Job:
    id: int
    module: ModuleSpec
    cancel: threading.Event = field(default_factory=threading.Event)
    status: str = "starting"
    run_dir: str = ""
    result: RunOutcome | None = None
    error: str | None = None
    thread: threading.Thread | None = None


class LabConsole(cmd.Cmd):
    intro = (
        "Secure Kernel Lab console\n"
        "Type 'modules' to list workflows, 'use <module>' to select one, and 'help' for commands."
    )
    ruler = "-"

    def __init__(
        self,
        config: Config,
        *,
        target_name: str | None,
        output: Output,
        show_banner: bool = True,
    ):
        super().__init__()
        self.config = config
        self.target_name = target_name
        self.output = output
        if show_banner and output.mode == "text":
            self.intro = render_banner(config, target_name, output) + "\n" + LabConsole.intro
        self.selected: ModuleSpec | None = None
        self.overrides: dict[str, Any] = {}
        self.jobs: dict[int, Job] = {}
        self._next_job = 1
        self._lock = threading.Lock()
        self._history: list[str] = []
        self._set_prompt()

    def _set_prompt(self) -> None:
        context = self.selected.id if self.selected else "main"
        self.prompt = f"sklab ({context}) > "

    def emptyline(self) -> None:
        return

    def precmd(self, line: str) -> str:
        if line.strip():
            self._history.append(line.rstrip())
        return line

    def _need_selected(self) -> ModuleSpec | None:
        if self.selected is None:
            self.output.event("error", "select a module with 'use <module>'")
        return self.selected

    def do_modules(self, _line: str) -> None:
        """List the numbered module catalog."""
        self.output.table(module_rows(), ("#", "module", "category", "risk", "title"))

    def do_use(self, line: str) -> None:
        """Select a module by id or number: use kd.manual"""
        try:
            self.selected = resolve_module(line.strip())
        except LabError as error:
            self.output.event("error", str(error))
            return
        self.overrides.clear()
        self._set_prompt()
        self.output.event("ok", f"using {self.selected.id}", risk=self.selected.risk)

    def do_show(self, line: str) -> None:
        """Show modules, current options, or module details."""
        value = line.strip()
        if value in {"", "options"}:
            module = self._need_selected()
            if module is None:
                return
            options = module.options(self.overrides)
            rows = [
                {
                    "option": name,
                    "value": value,
                    "source": "set" if name in self.overrides else "default",
                }
                for name, value in options.items()
            ]
            if rows:
                self.output.table(rows, ("option", "value", "source"))
            else:
                self.output.event("info", "this module has no default options")
            return
        if value == "modules":
            self.do_modules("")
            return
        try:
            module = resolve_module(value)
        except LabError as error:
            self.output.event("error", str(error))
            return
        self.output.event("info", f"{module.id}: {module.title}", category=module.category, risk=module.risk)
        print(module.description, file=self.output.stream)

    def do_set(self, line: str) -> None:
        """Set an option: set steps 12 (or set steps=12)."""
        value = line.strip()
        if not value:
            self.output.event("error", "usage: set NAME VALUE")
            return
        if "=" in value:
            name, raw = value.split("=", 1)
        else:
            parts = value.split(None, 1)
            if len(parts) != 2:
                self.output.event("error", "usage: set NAME VALUE")
                return
            name, raw = parts
        name = name.strip().replace("-", "_")
        self.overrides[name] = parse_scalar(raw.strip())
        self.output.event("ok", f"{name} => {self.overrides[name]!r}")

    def do_unset(self, line: str) -> None:
        """Remove a locally set option: unset steps"""
        name = line.strip().replace("-", "_")
        if self.overrides.pop(name, None) is None:
            self.output.event("warning", f"{name!r} was not set")
        else:
            self.output.event("ok", f"unset {name}")

    def do_back(self, _line: str) -> None:
        """Return to the main context and clear current options."""
        self.selected = None
        self.overrides.clear()
        self._set_prompt()

    def do_check(self, _line: str) -> None:
        """Run prerequisite checks for the selected module."""
        module = self._need_selected()
        if module is None:
            return
        try:
            rows = check_module(
                self.config,
                module,
                target_name=self.target_name,
                overrides=self.overrides,
            )
        except LabError as error:
            self.output.event("error", str(error))
            return
        self.output.table(rows, ("status", "name", "detail"))
        self.output.event("ok" if passed(rows) else "error", "checks passed" if passed(rows) else "checks failed")

    def _confirm(self, module: ModuleSpec) -> bool:
        if module.risk == "read-only":
            return True
        answer = input(f"Run {module.id} ({module.risk}) against the configured target? [y/N] ")
        return answer.strip().lower() in {"y", "yes"}

    def _run_job(self, job: Job, overrides: dict[str, Any]) -> None:
        def context_ready(context) -> None:
            job.run_dir = str(context.run_dir)
            job.status = "running"

        try:
            job.result = execute_module(
                self.config,
                job.module,
                target_name=self.target_name,
                overrides=overrides,
                output=self.output,
                assume_yes=True,
                cancel_event=job.cancel,
                on_context=context_ready,
            )
            job.status = "completed"
        except LabError as error:
            job.error = str(error)
            job.status = "cancelled" if job.cancel.is_set() else "failed"
            self.output.event("warning" if job.cancel.is_set() else "error", f"job {job.id}: {error}")
        except Exception as error:
            job.error = f"{type(error).__name__}: {error}"
            job.status = "failed"
            self.output.event("error", f"job {job.id}: {job.error}")

    def do_run(self, line: str) -> None:
        """Run the selected module. The manual KD module runs as a background job."""
        module = self._need_selected()
        if module is None:
            return
        tokens = shlex.split(line, posix=False)
        if tokens:
            self.output.event("error", "run takes no arguments; use 'set NAME VALUE' first")
            return
        background = module.id == "kd.manual"
        if not self._confirm(module):
            self.output.event("warning", "run cancelled")
            return
        if background:
            with self._lock:
                job = Job(self._next_job, module)
                self.jobs[job.id] = job
                self._next_job += 1
            thread = threading.Thread(
                target=self._run_job,
                args=(job, dict(self.overrides)),
                name=f"sklab-job-{job.id}",
            )
            job.thread = thread
            thread.start()
            self.output.event("ok", f"started job {job.id}", module=module.id)
            return
        job = Job(0, module)
        self._run_job(job, dict(self.overrides))

    def do_jobs(self, _line: str) -> None:
        """List background jobs."""
        rows = [
            {
                "job": job.id,
                "module": job.module.id,
                "status": job.status,
                "run_dir": job.run_dir,
            }
            for job in self.jobs.values()
        ]
        if rows:
            self.output.table(rows, ("job", "module", "status", "run_dir"))
        else:
            self.output.event("info", "no jobs")

    def do_sessions(self, _line: str) -> None:
        """List managed KD jobs and their latest session/pipe information."""
        rows: list[dict[str, Any]] = []
        for job in self.jobs.values():
            if job.module.id != "kd.manual":
                continue
            session = ""
            pipe = ""
            if job.run_dir:
                try:
                    manifest = json.loads(
                        (Path(job.run_dir) / "manifest.json").read_text(encoding="utf-8")
                    )
                    session = manifest.get("session_id", "")
                    pipe = manifest.get("pipe", "")
                except (OSError, ValueError):
                    pass
            rows.append({"job": job.id, "status": job.status, "session": session, "pipe": pipe})
        if rows:
            self.output.table(rows, ("job", "status", "session", "pipe"))
        else:
            self.output.event("info", "no managed KD sessions")

    def do_stop(self, line: str) -> None:
        """Request a background job to stop: stop 1"""
        try:
            job = self.jobs[int(line.strip())]
        except (ValueError, KeyError):
            self.output.event("error", "usage: stop JOB_ID")
            return
        if job.status not in {"starting", "running"}:
            self.output.event("warning", f"job {job.id} is already {job.status}")
            return
        job.cancel.set()
        self.output.event("warning", f"stop requested for job {job.id}")

    def do_banner(self, _line: str) -> None:
        """Print the banner again, with current driver state."""
        print(render_banner(self.config, self.target_name, self.output), file=self.output.stream)

    def do_driver(self, line: str) -> None:
        """Report, start or stop h3probe: driver [status|start|stop]"""
        parts = line.split()
        action = parts[0] if parts else "status"
        if action not in {"status", "start", "stop"} or len(parts) > 2:
            self.output.event("error", "usage: driver [status|start|stop] [service]")
            return

        def confirm(prompt: str) -> bool:
            return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}

        try:
            code = run_driver(
                self.config,
                action,
                parts[1] if len(parts) == 2 else None,
                self.output,
                confirm=confirm,
            )
        except LabError as error:
            self.output.event("error", str(error))
            return
        if action != "status":
            self.output.event("ok" if code == 0 else "warning", f"driver {action} {'done' if code == 0 else 'incomplete'}")

    def do_vm(self, line: str) -> None:
        """Report or reset the selected disposable VM disk: vm [status|reset]"""
        parts = line.split()
        action = parts[0] if parts else "status"
        if action not in {"status", "reset"} or len(parts) > 1:
            self.output.event("error", "usage: vm [status|reset]")
            return
        if action == "reset":
            active = [
                job.id for job in self.jobs.values() if job.status in {"starting", "running"}
            ]
            if active:
                self.output.event("error", f"active jobs {active}; stop them before resetting the VM")
                return

        def confirm(prompt: str) -> bool:
            return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}

        try:
            run_vm(
                self.config,
                self.target_name,
                action,
                self.output,
                confirm=confirm,
            )
        except LabError as error:
            self.output.event("error", str(error))

    def do_history(self, _line: str) -> None:
        """Show console command history."""
        for index, value in enumerate(self._history, 1):
            print(f"{index:4}  {value}", file=self.output.stream)

    def do_exit(self, _line: str) -> bool:
        """Exit when no background target-control job is active."""
        active = [job.id for job in self.jobs.values() if job.status in {"starting", "running"}]
        if active:
            self.output.event("warning", f"active jobs {active}; stop them before exiting")
            return False
        return True

    def do_quit(self, line: str) -> bool:
        """Alias for exit."""
        return self.do_exit(line)

    def do_EOF(self, line: str) -> bool:
        print(file=self.output.stream)
        return self.do_exit(line)
