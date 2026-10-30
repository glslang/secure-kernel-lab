"""The console banner.

ASCII only, on purpose: a console on this bench is as likely to be cp1252 as UTF-8, and a banner that
raises `UnicodeEncodeError` before the prompt appears is a worse banner than a plain one.
"""

from __future__ import annotations

import random
from typing import Callable

from . import __version__


LOGO = (
    r"         __   __      __    ",
    r"   _____/ /__/ /___ _/ /_   ",
    r"  / ___/ //_/ / __ `/ __ \  ",
    r" (__  ) ,< / / /_/ / /_/ /  ",
    r"/____/_/|_/_/\__,_/_.___/   ",
)

# The trust boundary the lab works across, with the root partition's view of it marked.
PANEL = (
    (".--------------------------------------.", "dim"),
    ("| VTL1 | securekernel.exe    trustlets | <- H3", "magenta"),
    ("|======#===============================|", "yellow"),
    ("| VTL0 | ntoskrnl.exe        userland  |", "cyan"),
    ("'---------- hvix64 :: root ------------'", "dim"),
)

TAGLINES = (
    "VTL0 is the control. VTL1 is the question.",
    "CR3 is discovered, not asserted.",
    "Every intercept leaves with its removal.",
    "Read the uptime twice.",
    "A refusal you cannot name is still a refusal.",
    "Absence of failure is not success.",
)

Paint = Callable[..., str]


def _plain(text: str, *_styles: str) -> str:
    return text


def render(
    *,
    modules: dict[str, int],
    target: str | None,
    drivers: dict[str, str],
    paint: Paint = _plain,
    tagline: str | None = None,
) -> str:
    lines = [""]
    for logo, (panel, style) in zip(LOGO, PANEL):
        lines.append(paint(logo, "bold", "cyan") + "  " + paint(panel, style))
    lines.append("")

    counts = " | ".join(f"{count} {category}" for category, count in modules.items())
    states = " | ".join(f"{name} {state}" for name, state in drivers.items())
    facts = [
        f"secure-kernel-lab {__version__}",
        f"{counts} modules",
        f"target {target}" if target else "no target configured",
        states or "no drivers configured",
    ]
    width = max(len(fact) for fact in facts) + 2
    for index, fact in enumerate(facts):
        lead = "       " if index == 0 else "+ -- --"
        lines.append(
            paint(lead + "=[ ", "dim") + paint(fact.ljust(width), *_fact_style(fact)) + paint("]", "dim")
        )
    lines.append("")
    lines.append(paint(f'  "{tagline or random.choice(TAGLINES)}"', "dim", "italic"))
    lines.append("")
    return "\n".join(lines)


def _fact_style(fact: str) -> tuple[str, ...]:
    if fact.startswith("h3probe"):
        if "h3probe running" in fact:
            return ("green",)
        return ("yellow",) if "h3probe stopped" in fact else ("red",)
    return ()
