# Architecture

The application has three layers:

1. `sklab.cli` and `sklab.console` expose one module catalog to automation and operators.
2. Module adapters check the exact target, create an immutable run directory, generate a
   least-authority policy, and invoke a `windbg-mcp` MCP or CLI entry point.
3. `windbg-mcp` owns DbgEng, h3probe's typed ABI, both built-in providers, and every driver read or
   write. Sklab owns VM/service lifecycle, guest triggers, orchestration, and evidence.

The provider boundary is explicit. A policy admits `builtin:h3probe` under
`builtin_transports`; it does not admit a Python interpreter. The worker expands that reserved name
to its own current executable and the coordinates it discovered, which prevents provider/server
build skew during executable replacement. Custom transports remain available to other clients.

The control and memory providers are child roles, not supervisor libraries. Each holds one device
handle and speaks a bounded line protocol. A provider that exits, wedges in an IOCTL, or returns a
malformed packet costs one operation/session, not the supervisor or another debuggee. The server
does not install, start, stop, or distribute a driver binary.

Sklab's `drivers` module talks only to the service control manager. `doctor` checks the service
image/hash and delegates readiness to `windbg-mcp --sk-control-probe --transport builtin:h3probe`.
Discovery is likewise the isolated `--sk-discover-identity` role. The post-release audit pauses and
resumes the exact allowlisted VM, but its identity, register snapshot, Secure Kernel base discovery,
and guarded-text reads run in the bounded `--sk-h3-audit` role.

Live memory remains bound to this boot's vmwp PID, its process-local VID partition handle, and the
partition ID. The driver checks process/handle ownership and its exact VID build pin before serving
typed `ok`, `not-present`, `refused`, `error`, or `identity` answers. The hypercall route remains the
independent refusing control. Guarded writes require both provider capability and policy authority.

Every target-control module requires `disposable = true`, exact VM identity, pinned profiles and
images, and confirmation (or `--yes`). Run manifests and transcripts redact credential/key-shaped
fields. Machine-local configuration, images, symbols, disks, dumps, credentials, and evidence stay
outside Git.

The old out-of-session register and transition experiments were retired rather than adding a raw
register API to sklab. Driver qualification moved to windbg-mcp beside the source and ABI. Sklab's
current live tier, KD tiers, M8 runner, and release audit are ordinary clients of that boundary.

See [`m8-runbook.md`](m8-runbook.md) for operator setup and recovery, and
[`h3probe-only-plan.md`](h3probe-only-plan.md) for the historical provider derivation.
