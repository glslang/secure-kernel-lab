from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Any, Callable

from .config import Config, Target
from .context import RunContext
from .errors import Cancelled, LabError, RecoveryRequired
from .manifest import RunManifest
from .modules.spec import ModuleSpec
from .output import Output


@dataclass(frozen=True)
class RunOutcome:
    module: str
    result: dict[str, Any]
    run_dir: Path


def select_target(config: Config, name: str | None) -> Target | None:
    if name is not None:
        return config.target(name)
    if config.targets:
        return config.target(None)
    return None


def execute_module(
    config: Config,
    module: ModuleSpec,
    *,
    target_name: str | None,
    overrides: dict[str, Any],
    output: Output,
    assume_yes: bool,
    cancel_event: threading.Event | None = None,
    on_context: Callable[[RunContext], None] | None = None,
) -> RunOutcome:
    target = select_target(config, target_name)
    options = module.options(overrides)
    manifest = RunManifest.create(config, module.id, target, options)
    context = RunContext(
        config=config,
        output=output,
        manifest=manifest,
        target=target,
        assume_yes=assume_yes,
        cancel_event=cancel_event,
    )
    if on_context is not None:
        on_context(context)
    output.event("phase", f"running {module.id}", run_dir=str(context.run_dir))
    try:
        if module.run is None:
            raise RuntimeError(f"module {module.id} has no run implementation")
        result = module.run(context, options)
        manifest.finish("success", output=result)
        output.event("ok", f"{module.id} completed", run_dir=str(context.run_dir))
        return RunOutcome(module.id, result, context.run_dir)
    except Cancelled as error:
        manifest.finish("cancelled", error=str(error))
        raise
    except LabError as error:
        manifest.finish(
            "recovery_required" if isinstance(error, RecoveryRequired) else "failed",
            error=str(error),
        )
        raise
    except KeyboardInterrupt:
        manifest.finish("cancelled", error="keyboard interrupt")
        raise
    except Exception as error:
        manifest.finish("internal_error", error=f"{type(error).__name__}: {error}")
        raise


def check_module(
    config: Config,
    module: ModuleSpec,
    *,
    target_name: str | None,
    overrides: dict[str, Any],
) -> list[dict[str, Any]]:
    target = select_target(config, target_name)
    manifest = RunManifest(
        config.paths.state_root / "check" / "manifest.json",
        {"result": "check-only"},
    )
    context = RunContext(config, Output(), manifest, target)
    if module.check is None:
        return []
    return module.check(context, module.options(overrides))
