# The h3probe-only migration's retired providers and differential

These files were current until the h3probe-only migration ([`docs/h3probe-only-plan.md`](../../docs/h3probe-only-plan.md))
and are kept for provenance. Like the rest of `legacy/`, nothing imports, installs or runs them, and
they would not run from here: they import modules by their old paths.

| File | What it was |
|---|---|
| `hvmm.py` | `sklab.hvmm`: guest-physical reads and writes through LiveCloudKd's `hvmm.sys`, with a VID handle duplicated out of vmwp; the reader that answered a GPA with no RAM behind it as a page of zeros |
| `hvmm_gpa.py`, `hvmm_gpa_server.py` | the bench's hvmm source and its `windbg-mcp-gpa/1` transport, the default live-memory provider before the migration |
| `s5w_gpa_server_pinned_vtl.py` | the hvlib-bootstrapped transport: hvlib's own reads, the explicit hvmm reader, and the refusing-hypercall mode, which `gpa_server.py --pages hypercall` now serves without hvlib |
| `h3_memory_differential.py` | `measure.h3-memory` (Phase 1) and the first `validate.h3-memory` (Phase 2) as they ran: every page through h3probe and through hvmm, exact agreement required |
| `h3_migration_differential.py` | the corpus records and Phase 1/2 verdicts those modules used |
| `test_hvmm.py`, `test_live_decode_providers.py`, `test_h3_migration_differential.py` | their tests, as they last passed |

The differential is the evidence that the memory operation reads what hvmm read, and it is what the
plan names as the migration's oracle. It cannot run once hvmm is uninstalled, which is the end state,
so the product's `validate.h3-memory` now checks h3probe against the hypervisor's own `HvCallReadGpa`
and the pinned Secure Kernel image instead. The runs that passed with hvmm, and what each measured,
are listed in the plan.

To revive a comparison, promote it into a named module behind an explicitly named configuration, as
`legacy/README.md` describes, rather than importing from here.
