"""The hvmm differential of the h3probe-only migration, as it ran on 2026-10-29.

`measure.h3-memory` (Phase 1) and the first `validate.h3-memory` (Phase 2) read every page through
h3probe and through LiveCloudKd's hvmm and required exact agreement. They passed (runs
20261029T175141-measure-h3-memory-b269f5 and 20261029T180536-validate-h3-memory-b13919), and once
hvmm was uninstalled they could not run, so the product's validation now checks h3probe against the
hypervisor's own `HvCallReadGpa` and the pinned image instead. This is the code that produced the
differential evidence, kept for provenance. It is not imported and does not run from here.
"""

def _h3_corpus(
    ctx: RunContext,
    k4: Any,
    h3: Any,
    memory: Any,
    probe: Any,
    pid: int,
    handle: int,
    partition: int,
    map_limit: int,
    map_step: int,
    result: dict[str, Any],
    report: Path,
) -> tuple[dict[str, int], dict[str, int], list[dict[str, Any]]]:
    """The paused target's corpus pages, controls and VID range map, recorded into `result`.

    The Secure Kernel pages come from its live IDT through hvmm, the comparison reader; the edges
    of RAM come from VID's own ranges, mapped through h3probe's translate probe.
    """
    target = ctx.target
    assert target is not None
    vtl1 = memory.vtl1_identity(partition, target.vp)
    source = memory.HvmmSource(pid, handle)
    try:
        guest = memory.GuestVirtual(source, int(vtl1["cr3"]))
        base, base_evidence = memory.find_secure_kernel_base(
            guest,
            int(vtl1["idtr_base"]),
            int(vtl1["idtr_limit"]),
            target.secure_kernel_image,
        )
        handler_va = int(str(base_evidence["handler"]), 0)
        code_page = guest.translate(handler_va) & ~0xFFF
    finally:
        source.close()

    # VID's own ranges come first, and the corpus's edges are read from them: K3 went from
    # 4 GiB to 8 GiB under an end of RAM written in as a constant.
    configured = int(k4.ps(f"(Get-VM -Id '{target.vm_id}' -ErrorAction Stop).MemoryStartup"))
    limit = map_limit or configured + 0x140000000  # the RAM, a gap of at most 4 GiB, and 1 GiB
    started = time.monotonic()
    runs = h3_migration.range_map(
        lambda gpn: h3_memory_probe.translate(probe, pid, handle, gpn << 12),
        limit >> 12,
        map_step,
    )
    ram_runs = [run for run in runs if run["kind"] == "memory-block"]
    end_of_ram = max((int(run["end"], 16) for run in ram_runs), default=0)
    gaps = [
        int(run["start"], 16)
        for run in runs
        if run["kind"] == "none" and int(run["start"], 16) < 0x100000000
    ]
    result["vid_ranges"] = {
        "limit": hex(limit),
        "step_pages": hex(map_step),
        "dense_below": "0x100000",
        "configured_memory": hex(configured),
        "ram_bytes": hex(sum(run["pages"] for run in ram_runs) << 12),
        "end_of_ram": hex(end_of_ram),
        "seconds": round(time.monotonic() - started, 3),
        "runs": runs,
    }
    atomic_json(report, result)
    if not ram_runs or end_of_ram >= limit:
        raise ExecutionFailure(f"VID's RAM reaches the map's limit 0x{limit:x}, so its end is unseen")
    if not gaps:
        raise ExecutionFailure("VID reports no range-free gap below 4 GiB to stand for the device gap")

    addresses = {
        "mapped_code": code_page,
        "mapped_data": int(vtl1["cr3"]) & ~0xFFF,
        # Page 0: hvmm reads zeros there and HvCallReadGpa accepts it (sklab.backing).
        "mapped_zero": 0,
        # Inside the legacy hole NT leaves out of its runs, measured backed on K3.
        "ram_hole": 0xA0000,
        "device_gap": gaps[0],
        "end_of_ram": end_of_ram,
        # The page that exposed hvlib's open-time 4 GiB bound.
        "above_4gib": 0x107FFF000,
    }

    status, vtl0_cr3, _ = probe.get(partition, 0, h3.REGISTERS["cr3"], target.vp)
    if status != 0:
        raise ExecutionFailure(f"VTL0 CR3 positive control failed: HV_STATUS 0x{status:04x}")
    controls = {
        "vtl0_positive_control": vtl0_cr3 & ~0xFFF,
        "last_ram_page": end_of_ram - 0x1000,
        "local_apic": 0xFEE00000,
        "far_above_ram": end_of_ram + 0x100000000,
    }
    result["addresses"] = {name: hex(gpa) for name, gpa in {**addresses, **controls}.items()}
    result["addresses"].update(
        secure_kernel_base=hex(base),
        secure_kernel_handler=hex(handler_va),
    )
    result["base_discovery"] = base_evidence
    return addresses, controls, runs


def h3_memory_measurement(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Phase 1: measure the in-vmwp VID page read against hvmm and the hypervisor's backing oracle.

    One boot of the disposable target. While it is paused: the corpus addresses and controls are
    read through hvmm, asked of `HvCallReadGpa`, translated by VID, and read by h3probe; VID's GPA
    ranges are mapped; and a seeded sample of RAM pages is read through both readers and compared.
    Then it runs for 60 seconds and is audited before it is turned off. Read-only throughout: the
    only change either reader makes is h3probe's scratch pages in vmwp, freed before each call ends.
    """
    checks = _write_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("h3 memory measurement prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    sample_count = int(options.get("sample_pages", 64))
    seed = int(options.get("sample_seed", int(time.time())))
    map_limit = int(options.get("map_limit_gpa", 0))  # 0: derived from the VM's memory
    map_step = int(options.get("map_step_pages", 0x40))
    ctx.confirm(
        f"Boot {target.vm_name}, compare read-only VID and hvmm pages, audit it for 60 seconds, "
        "and return it to Off?"
    )

    runner, configured = bench_bridge.configure_runner(ctx, "run_k3_sk_live")
    k4 = runner.k4
    h3 = configured["h3"]
    # Not configured["memory"], which is the hvlib comparison server: the direct helpers are here.
    memory = bench_bridge._module("hvmm_gpa")
    report = ctx.run_dir / "h3-memory-measurement.json"
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    result: dict[str, Any] = {
        "schema": "secure-kernel-lab.h3-vid-read-measurement.v2",
        "target": target.name,
        "vm_id": target.vm_id,
        "operation": (
            "per page: VID translate of gpa >> 12, the memory-block handle from the partition's "
            "table, one VidReadMemoryBlockPageRange page, and a second translate; no write, "
            "registration, intercept, or retained mapping"
        ),
        "probe_version": h3_memory_probe.VERSION,
        "host_images": {
            "vid.sys": _sha256_file(system / "drivers" / "vid.sys"),
            "vid.dll": _sha256_file(system / "vid.dll"),
            "vmwp.exe": _sha256_file(system / "vmwp.exe"),
        },
        "options": {
            "sample_pages": sample_count,
            "sample_seed": seed,
            "map_limit_gpa": hex(map_limit),
            "map_step_pages": hex(map_step),
        },
        "hvlib_loaded_before": hvmm.module_loaded("hvlib.dll"),
        "comparisons": {},
        "controls": {},
    }
    for service in (ctx.config.drivers.h3probe_service, ctx.config.drivers.hvmm_service):
        state = drivers.status(service)
        image = state.image
        result.setdefault("drivers", {})[service] = {
            "state_before": state.state,
            "image": str(image or ""),
            "sha256": _sha256_file(image) if image is not None else None,
        }
    atomic_json(report, result)
    if result["hvlib_loaded_before"]:
        raise ExecutionFailure("hvlib.dll was already loaded before the no-hvlib measurement")

    booted = paused = False
    pid = 0
    probe = source = duplicate = device = None
    # start_bench starts the VM before it waits for a healthy boot, and can fail in that wait. Checked
    # Off here, a VM that is not Off after it raises is this run's, and is cleaned up below.
    if k4.vm_state() != "Off":
        raise PrerequisiteError(f"{target.vm_name} must be Off before the measurement boots it")
    try:
        try:
            pid, uptime = k4.start_bench()
        finally:
            booted = k4.vm_state() != "Off"
        vnd, handle, partition, how = runner.discovery(pid)
        result["boot"] = {"vmwp_pid": pid, "uptime_seconds": uptime}
        result["identity"] = {
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "discovery": how,
        }
        probe = h3.Probe()
        result["state_before"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_before"] = k4.health(pid, "before-h3-memory")
        atomic_json(report, result)

        k4.pause_vm()
        paused = True
        addresses, controls, runs = _h3_corpus(
            ctx, k4, h3, memory, probe, pid, handle, partition, map_limit, map_step, result, report
        )

        duplicate = hvmm.DuplicatedHandle(pid, handle)
        device = hvmm.Device()
        old_reader = hvmm.Reader(device, duplicate.value, partition)
        oracle = backing.Hypervisor(probe, partition)

        def compare(gpa: int) -> tuple[dict[str, Any], bytes | None, str | None, str]:
            old_data, old_failure = old_reader.read(gpa, hvmm.PAGE)
            _backed, answer = oracle.ask(gpa)
            translation = h3_memory_probe.translate(probe, pid, handle, gpa)
            candidate = h3_memory_probe.read_probe(probe, pid, handle, gpa)
            return (
                {
                    "gpa": hex(gpa),
                    "translate": translation.record(),
                    "h3": candidate.record(),
                    "hvmm": {
                        "failure": old_failure,
                        "all_zero": old_data == hvmm.ZERO_PAGE if old_data is not None else None,
                        "sha256": hashlib.sha256(old_data).hexdigest() if old_data is not None else None,
                    },
                    "backing": answer,
                    "data_matches_hvmm": candidate.data == old_data
                    if candidate.succeeded and old_data is not None
                    else None,
                },
                old_data,
                old_failure,
                answer,
            )

        corpus_samples = []
        for name, gpa in addresses.items():
            entry, old_data, old_failure, answer = compare(gpa)
            result["comparisons"][name] = entry
            corpus_samples.append(
                h3_migration.page_record(name, gpa, old_data, old_failure, backing=answer)
            )
        for name, gpa in controls.items():
            result["controls"][name] = compare(gpa)[0]
        result["corpus"] = {
            "schema": h3_migration.SCHEMA,
            "target": target.name,
            "boot_before": result["boot"],
            "identity_before": result["identity"],
            "state_before": result["state_before"],
            "drivers": result["drivers"],
            "samples": corpus_samples,
        }
        h3_migration.validate(result["corpus"])
        atomic_json(report, result)

        pages = h3_migration.sample_pages(runs, sample_count, seed)
        disagreements: list[dict[str, Any]] = []
        agreed = 0
        for gpa in pages:
            old_data, old_failure = old_reader.read(gpa, hvmm.PAGE)
            candidate = h3_memory_probe.read_probe(probe, pid, handle, gpa)
            if candidate.succeeded and old_data is not None and candidate.data == old_data:
                agreed += 1
            elif len(disagreements) < 16:
                disagreements.append(
                    {
                        "gpa": hex(gpa),
                        "h3": candidate.record(),
                        "hvmm_failure": old_failure,
                        "hvmm_sha256": hashlib.sha256(old_data).hexdigest() if old_data is not None else None,
                    }
                )
        result["sample"] = {
            "seed": seed,
            "pages": len(pages),
            "agreed": agreed,
            "above_4gib": sum(1 for gpa in pages if gpa >= 0x100000000),
            "disagreements": disagreements,
        }

        text_after, text_failure = old_reader.read(addresses["mapped_code"], hvmm.PAGE)
        result["vtl1_text"] = {
            "gpa": hex(addresses["mapped_code"]),
            "sha256_before": result["comparisons"]["mapped_code"]["hvmm"]["sha256"],
            "sha256_after": hashlib.sha256(text_after).hexdigest() if text_after is not None else None,
            "failure_after": text_failure,
        }
        result["hvlib_loaded_after"] = hvmm.module_loaded("hvlib.dll")
        atomic_json(report, result)
        device.close()
        device = None
        duplicate.close()
        duplicate = None

        k4.resume_vm()
        paused = False
        time.sleep(60)
        result["state_after"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_after_60s"] = k4.health(pid, "after-h3-memory-60s")
        result["same_boot"] = result["health_before"]["pid"] == result["health_after_60s"]["pid"]
        result["phase1"] = h3_migration.phase1_verdict(result)
        result["result"] = "pass" if result["phase1"]["passed"] else "fail"
        atomic_json(report, result)
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["result"] = "error"
        if booted:
            try:
                result["vm_at_error"] = k4.vm_json()
            except Exception as state_error:
                result["vm_at_error"] = f"unreadable: {state_error}"
        atomic_json(report, result)
        raise
    finally:
        for resource in (source, device, duplicate, probe):
            if resource is not None:
                try:
                    resource.close()
                except Exception as error:
                    result.setdefault("close_errors", []).append(str(error))
        if booted:
            if paused and k4.vm_state() == "Paused":
                k4.resume_vm()
            # Nothing here wrote to the guest, so there is nothing to restore before power-off.
            result.update(_stop_read_only_target(k4, target.vm_id))
            atomic_json(report, result)
    if result["result"] != "pass":
        failed = [name for name, ok in result["phase1"]["criteria"].items() if not ok]
        raise ExecutionFailure(f"Phase 1 criteria failed: {', '.join(failed)}; see {report}")
    return {"report": str(report), **result}


_H3_READ_LOOP = """
import sys
from sklab import h3_memory
device = h3_memory.Device()
reader = h3_memory.Reader(device, int(sys.argv[1]), int(sys.argv[2], 0), int(sys.argv[3], 0))
reads = 0
while True:
    data, failure = reader.read(int(sys.argv[4], 0), h3_memory.PAGE)
    if failure is not None:
        print("FAIL", failure, flush=True)
        raise SystemExit(1)
    reads += 1
    if reads == 1:
        print("READY", flush=True)
"""


def _h3_page(reader: h3_memory.Reader, gpa: int) -> tuple[bytes | None, dict[str, Any]]:
    data, answer, failure = reader.chunk(gpa, h3_memory.PAGE)
    record: dict[str, Any] = {
        "result": answer.result if answer is not None else "call-failed",
        "stage": answer.stage if answer is not None else None,
        "status": f"0x{answer.status:08x}" if answer is not None else None,
        "failure": failure,
        "all_zero": data == hvmm.ZERO_PAGE if data is not None else None,
        "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
    }
    return data, record


def _h3_refusals(device: Any, pid: int, handle: int, partition: int, gpa: int) -> dict[str, Any]:
    """What the driver itself answers to requests it must not serve. Read requests only."""
    request = h3_memory.REQUEST

    def ask(payload: bytes, out_size: int = h3_memory.READ_OUTPUT_SIZE) -> dict[str, Any]:
        try:
            raw = device.ioctl(h3_memory.IOCTL_H3_MEMREAD, payload, out_size)
            answer = h3_memory.parse_answer(raw, 8)
        except (OSError, ValueError) as error:
            return {"refused_by": "call", "detail": str(error)}
        data = raw[h3_memory.ANSWER.size :]
        return {
            "refused_by": "answer",
            "result": answer.result,
            "stage": answer.stage,
            "status": f"0x{answer.status:08x}",
            "data_zero": data == bytes(len(data)),
        }

    cases: dict[str, tuple[bytes, int, set[str]]] = {
        "wrong_partition": (request.pack(1, pid, handle, partition + 1, gpa, 8, 0), 0, {"identity/partition"}),
        "missing_process": (request.pack(1, 0xFFFFFFFC, handle, partition, gpa, 8, 0), 0, {"identity/process"}),
        "other_process": (request.pack(1, os.getpid(), handle, partition, gpa, 8, 0), 0, {"identity/handle", "identity/owner"}),
        "bad_handle": (request.pack(1, pid, 0xFFFFFC, partition, gpa, 8, 0), 0, {"identity/handle"}),
        "kernel_handle": (request.pack(1, pid, 0xFFFFFFFF80000004, partition, gpa, 8, 0), 0, {"identity/handle"}),
        "cross_page": (request.pack(1, pid, handle, partition, gpa | 0xFFF, 2, 0), 0, {"error/request"}),
        "oversized": (request.pack(1, pid, handle, partition, gpa, 0x1001, 0), 0, {"error/request"}),
        "empty": (request.pack(1, pid, handle, partition, gpa, 0, 0), 0, {"error/request"}),
        "bad_version": (request.pack(2, pid, handle, partition, gpa, 8, 0), 0, {"error/request"}),
        "reserved_set": (request.pack(1, pid, handle, partition, gpa, 8, 1), 0, {"error/request"}),
        "short_input": (request.pack(1, pid, handle, partition, gpa, 8, 0)[:-1], 0, {"call"}),
        "short_output": (request.pack(1, pid, handle, partition, gpa, 8, 0), h3_memory.ANSWER.size, {"call"}),
    }
    refusals: dict[str, Any] = {}
    for name, (payload, out_size, expected) in cases.items():
        got = ask(payload, out_size or h3_memory.READ_OUTPUT_SIZE)
        key = "call" if got["refused_by"] == "call" else f"{got['result']}/{got['stage']}"
        got["expected"] = sorted(expected)
        got["passed"] = key in expected and got.get("data_zero", True)
        refusals[name] = got
    return refusals


def _private_bytes(k4: Any, pid: int) -> int:
    return int(k4.ps(f"(Get-Process -Id {pid} -ErrorAction Stop).PrivateMemorySize64"))


def h3_memory_validation(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Phase 2: h3probe's memory operation, read-only, against hvmm, and how it is contained.

    One boot, paused while it is read: the corpus, the controls and a seeded sample of RAM through
    the product read and through hvmm; the requests the driver must refuse; a burst of reads against
    vmwp's private bytes; a reading process killed mid-loop; and an unload and reload of h3probe.
    Then 60 healthy seconds, and a restart, after which the old boot's identity must be refused.
    """
    checks = _write_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("h3 memory validation prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    sample_count = int(options.get("sample_pages", 256))
    seed = int(options.get("sample_seed", int(time.time())))
    burst = int(options.get("burst_reads", 2000))
    ctx.confirm(
        f"Boot {target.vm_name}, validate h3probe's read-only memory operation against hvmm, unload "
        "and reload h3probe, restart the VM once, and return it to Off?"
    )

    runner, configured = bench_bridge.configure_runner(ctx, "run_k3_sk_live")
    k4 = runner.k4
    h3 = configured["h3"]
    memory = bench_bridge._module("hvmm_gpa")
    report = ctx.run_dir / "h3-memory-validation.json"
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    service = ctx.config.drivers.h3probe_service
    result: dict[str, Any] = {
        "schema": "secure-kernel-lab.h3-memory-validation.v1",
        "target": target.name,
        "vm_id": target.vm_id,
        "abi_version": h3_memory.VERSION,
        "host_images": {
            "vid.sys": _sha256_file(system / "drivers" / "vid.sys"),
            "vid.dll": _sha256_file(system / "vid.dll"),
            "vmwp.exe": _sha256_file(system / "vmwp.exe"),
        },
        "options": {"sample_pages": sample_count, "sample_seed": seed, "burst_reads": burst},
        "hvlib_loaded_before": hvmm.module_loaded("hvlib.dll"),
        "comparisons": {},
        "controls": {},
    }
    for name in (service, ctx.config.drivers.hvmm_service):
        state = drivers.status(name)
        result.setdefault("drivers", {})[name] = {
            "state_before": state.state,
            "image": str(state.image or ""),
            "sha256": _sha256_file(state.image) if state.image is not None else None,
        }
    atomic_json(report, result)
    if result["hvlib_loaded_before"]:
        raise ExecutionFailure("hvlib.dll was already loaded before the no-hvlib validation")

    booted = paused = False
    pid = 0
    probe = duplicate = old_device = device = None
    if k4.vm_state() != "Off":
        raise PrerequisiteError(f"{target.vm_name} must be Off before the validation boots it")
    try:
        try:
            pid, uptime = k4.start_bench()
        finally:
            booted = k4.vm_state() != "Off"
        vnd, handle, partition, how = runner.discovery(pid)
        result["boot"] = {"vmwp_pid": pid, "uptime_seconds": uptime}
        result["identity"] = {
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "discovery": how,
        }
        probe = h3.Probe()
        result["state_before"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_before"] = k4.health(pid, "before-h3-memory-validation")
        atomic_json(report, result)

        k4.pause_vm()
        paused = True
        addresses, controls, runs = _h3_corpus(
            ctx, k4, h3, memory, probe, pid, handle, partition, 0, 0x40, result, report
        )
        device = h3_memory.Device()
        reader = h3_memory.Reader(device, pid, handle, partition)
        duplicate = hvmm.DuplicatedHandle(pid, handle)
        old_device = hvmm.Device()
        old_reader = hvmm.Reader(old_device, duplicate.value, partition)
        oracle = backing.Hypervisor(probe, partition)

        def compare(gpa: int) -> dict[str, Any]:
            old_data, old_failure = old_reader.read(gpa, hvmm.PAGE)
            _backed, answer = oracle.ask(gpa)
            data, record = _h3_page(reader, gpa)
            return {
                "gpa": hex(gpa),
                "h3": record,
                "hvmm": {
                    "failure": old_failure,
                    "all_zero": old_data == hvmm.ZERO_PAGE if old_data is not None else None,
                    "sha256": hashlib.sha256(old_data).hexdigest() if old_data is not None else None,
                },
                "backing": answer,
                "data_matches_hvmm": data == old_data if data is not None and old_data is not None else None,
            }

        for name, gpa in addresses.items():
            result["comparisons"][name] = compare(gpa)
        for name, gpa in controls.items():
            result["controls"][name] = compare(gpa)
        atomic_json(report, result)

        pages = h3_migration.sample_pages(runs, sample_count, seed)
        agreed = 0
        disagreements: list[dict[str, Any]] = []
        for gpa in pages:
            old_data, old_failure = old_reader.read(gpa, hvmm.PAGE)
            data, record = _h3_page(reader, gpa)
            if data is not None and data == old_data:
                agreed += 1
            elif len(disagreements) < 16:
                disagreements.append({"gpa": hex(gpa), "h3": record, "hvmm_failure": old_failure})
        result["sample"] = {
            "seed": seed,
            "pages": len(pages),
            "agreed": agreed,
            "above_4gib": sum(1 for gpa in pages if gpa >= 0x100000000),
            "disagreements": disagreements,
        }
        atomic_json(report, result)

        code_page = addresses["mapped_code"]
        result["refusals"] = _h3_refusals(device, pid, handle, partition, code_page)
        atomic_json(report, result)

        reference, _ = _h3_page(reader, code_page)
        before = _private_bytes(k4, pid)
        started = time.monotonic()
        same = sum(1 for _ in range(burst) if _h3_page(reader, code_page)[0] == reference)
        after = _private_bytes(k4, pid)
        result["leak"] = {
            "reads": burst,
            "identical": same,
            "seconds": round(time.monotonic() - started, 3),
            "vmwp_private_before": before,
            "vmwp_private_after": after,
            "delta": after - before,
            # Three scratch pages kept per read would be 12 KiB each; 4 MiB is a sixth of that.
            "passed": reference is not None and same == burst and after - before < 4 * 1024 * 1024,
        }
        atomic_json(report, result)

        child = subprocess.Popen(
            [sys.executable, "-c", _H3_READ_LOOP, str(pid), hex(handle), hex(partition), hex(code_page)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        lines: list[str] = []
        waiter = threading.Thread(
            target=lambda: lines.append(child.stdout.readline().strip() if child.stdout else ""),
            daemon=True,
        )
        waiter.start()
        waiter.join(timeout=30)
        first = lines[0] if lines else "no line within 30 s"
        time.sleep(1)
        child.kill()
        child.wait(timeout=30)
        after_kill, record = _h3_page(reader, code_page)
        result["cancellation"] = {
            "child_first_line": first,
            "child_exit": child.returncode,
            "read_after": record,
            "vmwp_private_after": _private_bytes(k4, pid),
            "passed": first == "READY" and after_kill == reference,
        }
        atomic_json(report, result)

        text_after, text_failure = old_reader.read(code_page, hvmm.PAGE)
        result["vtl1_text"] = {
            "gpa": hex(code_page),
            "sha256_before": result["comparisons"]["mapped_code"]["hvmm"]["sha256"],
            "sha256_after": hashlib.sha256(text_after).hexdigest() if text_after is not None else None,
            "failure_after": text_failure,
        }
        for resource in (old_device, duplicate):
            resource.close()
        old_device = duplicate = None
        result["hvlib_loaded_after"] = hvmm.module_loaded("hvlib.dll")

        # Every handle to the device is closed first: unloading under an open handle is not tested.
        device.close()
        probe.close()
        device = probe = None
        stopped = drivers.stop(service)
        try:
            h3_memory.Device().close()
            open_after_stop = "opened"
        except OSError as error:
            open_after_stop = str(error)
        started_again = drivers.start(service)
        device = h3_memory.Device()
        reader = h3_memory.Reader(device, pid, handle, partition)
        reloaded, record = _h3_page(reader, code_page)
        probe = h3.Probe()
        result["unload"] = {
            "state_after_stop": stopped.state,
            "open_after_stop": open_after_stop,
            "state_after_start": started_again.state,
            "read_after_reload": record,
            "passed": stopped.state == "stopped"
            and open_after_stop != "opened"
            and started_again.running
            and reloaded == reference,
        }
        atomic_json(report, result)

        k4.resume_vm()
        paused = False
        time.sleep(60)
        result["state_after"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_after_60s"] = k4.health(pid, "after-h3-memory-validation-60s")
        result["same_boot"] = result["health_before"]["pid"] == result["health_after_60s"]["pid"]
        device.close()
        probe.close()
        device = probe = None
        atomic_json(report, result)

        # A restart gives vmwp a new PID and the partition a new ID. The old boot's identity,
        # whole or with only the PID refreshed, must be refused as identity and never served.
        result["restart"] = {"stop": k4.stop_bench()}
        booted = False
        try:
            new_pid, new_uptime = k4.start_bench()
        finally:
            booted = k4.vm_state() != "Off"
        result["restart"].update(vmwp_pid=new_pid, uptime_seconds=new_uptime)
        device = h3_memory.Device()
        stale: dict[str, Any] = {}
        for name, owner in (("old_identity", pid), ("old_handle_and_partition", new_pid)):
            try:
                answer, data = h3_memory.read(device, owner, handle, partition, code_page, 8)
                stale[name] = {"result": answer.result, "stage": answer.stage, "bytes": len(data)}
            except (OSError, ValueError) as error:
                stale[name] = {"result": "call-failed", "detail": str(error)}
        result["identity_change"] = {
            "old": {"vmwp_pid": pid, "partition_handle": hex(handle), "partition_id": hex(partition)},
            "new_vmwp_pid": new_pid,
            "answers": stale,
            "passed": new_pid != pid and all(entry["result"] == "identity" for entry in stale.values()),
        }
        result["health_after_restart"] = k4.health(new_pid, "after-restart")
        result["phase2"] = h3_migration.phase2_verdict(result)
        result["result"] = "pass" if result["phase2"]["passed"] else "fail"
        atomic_json(report, result)
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["result"] = "error"
        if booted:
            try:
                result["vm_at_error"] = k4.vm_json()
            except Exception as state_error:
                result["vm_at_error"] = f"unreadable: {state_error}"
        atomic_json(report, result)
        raise
    finally:
        for resource in (old_device, duplicate, device, probe):
            if resource is not None:
                try:
                    resource.close()
                except Exception as error:
                    result.setdefault("close_errors", []).append(str(error))
        if booted:
            if paused and k4.vm_state() == "Paused":
                k4.resume_vm()
            # Nothing here wrote to the guest, so there is nothing to restore before power-off.
            result.update(_stop_read_only_target(k4, target.vm_id))
            atomic_json(report, result)
    if result["result"] != "pass":
        failed = [name for name, ok in result["phase2"]["criteria"].items() if not ok]
        raise ExecutionFailure(f"Phase 2 criteria failed: {', '.join(failed)}; see {report}")
    return {"report": str(report), **result}


