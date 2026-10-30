# Earlier work archive

Everything below `legacy/` is earlier work kept for provenance. It is not imported, installed, or
used by the `sklab` module catalog.

- `h3probe-migration/` holds the hvmm and hvlib providers the h3probe-only migration retired, and
  the h3probe-against-hvmm differential that qualified their replacement; its README lists them.
  It is source-preserving except that `s5w_gpa_server_pinned_vtl.py`'s bench-specific hvlib
  directory was replaced by an empty default, so it now needs `--dll-dir`.
- `inventory.json` records each archived file's path, size, and SHA-256 so later edits are obvious.

The archive excludes generated result JSON, transcripts, dumps, package/build caches, drivers and
executables, captures, and virtual disks. To revive anything here, promote it into a named module,
replace machine constants with configuration, add checks and manifests, and document why it is
current.
