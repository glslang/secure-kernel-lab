from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..context import RunContext


Check = Callable[[RunContext, dict[str, Any]], list[dict[str, Any]]]
Run = Callable[[RunContext, dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    title: str
    category: str
    risk: str
    description: str
    defaults: dict[str, Any] = field(default_factory=dict)
    check: Check | None = None
    run: Run | None = None

    def options(self, overrides: dict[str, Any]) -> dict[str, Any]:
        result = dict(self.defaults)
        result.update(overrides)
        return result

