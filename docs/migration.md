# Consolidation and provenance

The original bench mixed current workflows, exploratory probes, generated evidence, caches,
binaries, and virtual disks. Sklab first consolidated the proven Python provider path and then, as
part of windbg-mcp follow-up 133, moved the privileged path to its product owner.

Current ownership is:

- `windbg-mcp/drivers/h3probe`: driver source, build instructions, ABI hardening, and qualification;
- `windbg-mcp --sk-h3-control` and `--sk-h3-memory`: repository-owned provider roles;
- `windbg-mcp --sk-h3-audit`: bounded post-release privileged audit;
- sklab: VM/disk and service lifecycle, target configuration, guest trigger, policy generation,
  qualification orchestration, and evidence.

The old driver directory, Python device wrappers, provider scripts, direct register experiments,
and their unit tests were removed from sklab. The unresolved out-of-session register/transition
authority was decided by retirement, not by adding a second privileged API. The supported
`live.ambient` workflow now generates a boot-scoped input and runs windbg-mcp's exact Rust live
tier; KD and M8 already use the MCP surface.

Sklab keeps no driver binary. Its configuration may pin the service image hash and its CLI may
start or stop that explicitly named service, but no code under `src/` opens the device or carries a
control code. Generated policy names `builtin:h3probe`, never a Python interpreter.

Historical measurements and the old provider migration remain documented in
[`h3probe-only-plan.md`](h3probe-only-plan.md) and the provenance archive it references. They are
evidence, not runtime dependencies.
