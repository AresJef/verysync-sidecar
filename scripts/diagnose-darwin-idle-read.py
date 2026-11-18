#!/usr/bin/env python3
"""Compare native metric readers during isolated macOS resource pilots."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

ORDER = ("psutil", "combined", "combined", "psutil")
COUNTER_ROWS = tuple(range(10, 190, 15))
ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "tests/fixtures/resource-protocol.json"
C_SOURCE = Path(__file__).with_name("darwin-owned-sample.c")
SAMPLER = Path(__file__).with_name("measure-native-resources.py")


class Sample(ctypes.Structure):
    _fields_ = [
        ("birth_us", ctypes.c_uint64),
        ("rss_bytes", ctypes.c_uint64),
        ("user_ns", ctypes.c_uint64),
        ("system_ns", ctypes.c_uint64),
    ]

    def counters(self):
        return {"rss_bytes": self.rss_bytes, "cpu_user_s": self.user_ns / 1_000_000_000,
                "cpu_system_s": self.system_ns / 1_000_000_000}


def require_counter_agreement(before, sample, after):
    if not min(before["rss_bytes"], after["rss_bytes"]) <= sample["rss_bytes"] <= max(before["rss_bytes"], after["rss_bytes"]):
        raise RuntimeError("native RSS differs from reference bounds")
    for key in ("cpu_user_s", "cpu_system_s"):
        first, actual, last = (round(read[key] * 1_000_000_000) for read in (before, sample, after))
        if not first - 1_000 <= actual <= last + 1_000:
            raise RuntimeError("native CPU counter differs from reference bounds")


def read_json(path):
    return json.loads(path.read_bytes())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_sampler():
    spec = importlib.util.spec_from_file_location("frozen_sampler", SAMPLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OwnedReader:
    def __init__(self, library):
        self.library = ctypes.CDLL(str(library))
        prepare = self.library.prepare_owned_reader
        prepare.argtypes = []
        prepare.restype = ctypes.c_int
        if prepare() != 0:
            raise RuntimeError("native timebase initialization failed")
        self.read = self.library.read_owned_sample
        self.read.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(Sample)]
        self.read.restype = ctypes.c_int

    def bind(self, process, parent, reference):
        before = reference(process)
        sample = Sample()
        pointer = ctypes.byref(sample)
        if self.read(process.pid, parent, 0, pointer) != 0:
            raise RuntimeError("initial native ownership binding failed")
        after = reference(process)
        birth = sample.birth_us
        creation = before["creation_time"]
        if abs(birth - round(creation * 1_000_000)) > 1 or creation != after["creation_time"]:
            raise RuntimeError("native birth identity differs from the reference")
        require_counter_agreement(before, sample.counters(), after)
        if self.read(process.pid, parent + 1, birth, pointer) != 1:
            raise RuntimeError("native reader accepted the wrong parent")
        if self.read(process.pid, parent, birth + 1, pointer) != 2:
            raise RuntimeError("native reader accepted the wrong birth identity")
        return parent, birth, creation, sample, pointer

    def snapshot(self, process, binding):
        start = time.perf_counter_ns()
        parent, birth, creation, sample, pointer = binding
        if self.read(process.pid, parent, birth, pointer) != 0:
            raise RuntimeError("native identity ended, changed or could not be read")
        return {"pid": process.pid, "creation_time": creation, **sample.counters(),
                "read_start_ns": start, "read_end_ns": time.perf_counter_ns()}


def worker(args, protocol):
    sampler = load_sampler()
    reader = OwnedReader(args.library)
    reference, owned, fingerprint = sampler.snapshot, sampler.owned_processes, sampler.source_identity
    canonical, library = SAMPLER.read_bytes(), args.library.read_bytes()
    experiment_inputs = [canonical, Path(__file__).read_bytes(), C_SOURCE.read_bytes(), library,
                         args.scenario.encode(), args.reader.encode()]
    binding_digest = digest(b"\0".join(experiment_inputs))
    bindings = {}
    targets, brackets = [], []
    owner = sampler.dependency().Process()

    def admit(ready):
        targets.extend(owned(ready))
        for target in targets:
            lineage = target.parents()
            if not lineage or owner not in lineage:
                raise RuntimeError("resource fixture PID is outside this diagnostic process tree")
            bindings[target.pid] = reader.bind(target, lineage[0].pid, reference)
        if args.reader == "combined":
            sampler.snapshot = lambda process: reader.snapshot(process, bindings[process.pid])
        return targets

    def identity(*positional, **named):
        original = fingerprint(*positional, **named)
        if any(original[key] != value for key, value in protocol["source_inputs"].items()):
            raise ValueError("idle diagnostic source differs from the frozen workload")
        return {**original, "sampler_sha256": binding_digest, "original_sampler_sha256": digest(canonical),
                "diagnostic_only": True, "eligible_for_frozen_preparation_or_formal": False,
                "metric_reader": args.reader, "native_reader_sha256": digest(library)}

    if args.reader == "counter-check":
        class CounterSamples(sampler.BufferedSamples):
            def __init__(self, path):
                super().__init__(path)
                self.measured = 0

            def append(self, row):
                super().append(row)
                if row["phase"] != "measure":
                    return
                ordinal = self.measured
                self.measured += 1
                if ordinal not in COUNTER_ROWS:
                    return
                for target in targets:
                    before = reference(target)
                    combined = reader.snapshot(target, bindings[target.pid])
                    after = reference(target)
                    brackets.append({"row": ordinal, "before": before, "combined": combined, "after": after})
                    require_counter_agreement(before, combined, after)

        sampler.BufferedSamples = CounterSamples

    sampler.owned_processes = admit
    saved_argv = sys.argv
    sampler.source_identity = identity
    try:
        sys.argv = [str(SAMPLER), "--stage", "pilot", "--scenario", args.scenario,
                    "--repeats", str(protocol["scenarios"][args.scenario]["repeats"]), "--interval-ms",
                    str(protocol["interval_ms"]), "--toolchain", args.toolchain,
                    "--cargo", str(args.cargo), "--evidence-dir", str(args.evidence_dir)]
        code = sampler.main()
    finally:
        sys.argv = saved_argv
        if args.reader == "counter-check" and args.evidence_dir.is_dir():
            write_json(args.evidence_dir / "counter-brackets.json", brackets)
    if code in {0, 2}:
        assert len(bindings) == 2, "both held native processes must bind before measuring"
        for pid, (parent, birth, _, sample, pointer) in bindings.items():
            if reader.read(pid, parent, birth, pointer) == 0:
                raise RuntimeError("normally stopped owned process remained readable")
        write_json(args.evidence_dir / "reader-identity.json",
                   {"validated_processes": len(bindings), "wrong_parent_rejected": True,
                    "wrong_birth_rejected": True, "stopped_processes_rejected": True})
    return code


def verify_case(folder, mode, protocol, sampler, code):
    raw = read_json(folder / "preparation-result.json")
    rows = [json.loads(line) for line in (folder / "samples.jsonl").read_bytes().splitlines()]
    quality = sampler.summarize(raw, rows, protocol["quality"])
    if quality != read_json(folder / "quality-result.json") or quality["status"] != ("VALID" if code == 0 else "INSUFFICIENT"):
        raise RuntimeError("diagnostic raw metrics disagree with the original quality calculation")
    source = raw["source"]
    if (raw["formal_sample"] is not False or source["eligible_for_frozen_preparation_or_formal"] is not False
            or source["metric_reader"] != mode or source["sampler_sha256"] == protocol["source_inputs"]["sampler_sha256"]):
        raise RuntimeError("diagnostic identity was not isolated")
    identity = read_json(folder / "reader-identity.json")
    if identity != {"validated_processes": 2, "wrong_parent_rejected": True,
                    "wrong_birth_rejected": True, "stopped_processes_rejected": True}:
        raise RuntimeError("diagnostic ownership proof is incomplete")
    return {"directory": folder.name, "reader": mode, "exit_code": code,
            "quality": quality, "source": source, "native_identity_proof": identity,
            "identities": [[p["pid"], p["creation_time"]] for p in raw["identities"]],
            "engine_sha256": raw["events"][0]["engine_sha256"],
            "controller_sha256": bytes(raw["events"][0]["controller_sha256"]).hex(),
            "samples_sha256": digest((folder / "samples.jsonl").read_bytes())}


def verify_counter_brackets(folder):
    raw = read_json(folder / "preparation-result.json")
    records = read_json(folder / "counter-brackets.json")
    measured = [row for line in (folder / "samples.jsonl").read_bytes().splitlines()
                if (row := json.loads(line))["phase"] == "measure"]
    expected = [(row, (p["pid"], p["creation_time"])) for row in COUNTER_ROWS for p in raw["identities"]]
    if len(records) != len(expected):
        raise RuntimeError("active counter comparison missed a registered sample")
    earliest_completion_ns = raw["events"][1]["observed_ns"] + raw["events"][2]["elapsed_ns"]
    counters = {}
    for record, (row_number, identity) in zip(records, expected, strict=True):
        before, combined, after = (record[key] for key in ("before", "combined", "after"))
        if record["row"] != row_number or any((p["pid"], p["creation_time"]) != identity for p in (before, combined, after)):
            raise RuntimeError("active counter comparison changed owned process identity")
        if not (measured[row_number]["end_ns"] <= before["read_start_ns"] <= before["read_end_ns"]
                <= combined["read_start_ns"] <= combined["read_end_ns"] <= after["read_start_ns"]
                <= after["read_end_ns"] < earliest_completion_ns):
            raise RuntimeError("active counter comparison differs from its measurement interval")
        require_counter_agreement(before, combined, after)
        counters.setdefault(identity, []).append(combined["cpu_user_s"] + combined["cpu_system_s"])
    growth = [points[-1] - points[0] for points in counters.values()]
    if not all(value > 0 for value in growth):
        raise RuntimeError("both owned processes must exhibit active CPU growth")
    return {"observations": len(records), "cpu_growth_s": growth,
            "sha256": digest((folder / "counter-brackets.json").read_bytes())}


def compare(args, protocol):
    sampler = load_sampler()
    args.evidence_dir.mkdir(mode=0o700)
    started = time.monotonic()
    order = ORDER + ("counter-check",) if args.scenario != "idle" else ORDER
    result = {"formal_sample": False, "scenario": args.scenario, "order": order,
              "architecture": platform.machine(), "status": "ERROR", "cases": []}
    try:
        with tempfile.TemporaryDirectory(prefix="vss-owned-idle-reader-") as temporary:
            library = Path(temporary) / "owned.dylib"
            subprocess.run(["xcrun", "clang", "-O2", "-Wall", "-Wextra", "-Werror", "-dynamiclib",
                            str(C_SOURCE), "-o", str(library)], check=True, timeout=30)
            for slot, mode in enumerate(order):
                if time.monotonic() - started + 150 > 600:
                    result["status"] = "INSUFFICIENT_DIAGNOSTIC_TIME"
                    return 2
                folder = args.evidence_dir / f"case-{slot}-{mode}"
                command = [sys.executable, "-B", str(Path(__file__).resolve()),
                           "--cargo", str(args.cargo), "--toolchain", args.toolchain,
                           "--evidence-dir", str(folder), "--scenario", args.scenario,
                           "--reader", mode, "--library", str(library)]
                with (args.evidence_dir / f"case-{slot}.console.log").open("wb") as output:
                    code = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=False).returncode
                if code not in {0, 2}:
                    result["failed_case"] = {"directory": folder.name, "exit_code": code}
                    return code
                case = verify_case(folder, mode, protocol, sampler, code)
                if mode == "counter-check":
                    case["counter_comparison"] = verify_counter_brackets(folder)
                result["cases"].append(case)
        cases = result["cases"]
        catalog = read_json(ROOT / "tests/fixtures/verysync-v2.33.2-standard-binaries.json")
        package = {"arm64": "macos-arm64-standard", "x86_64": "macos-amd64-standard"}[platform.machine()]
        expected = next(item["binary_sha256"] for item in catalog["packages"] if item["id"] == package)
        if ({c["engine_sha256"] for c in cases} != {expected}
                or len({c["controller_sha256"] for c in cases}) != 1
                or len({tuple(i) for c in cases for i in c["identities"]}) != 2 * len(order)):
            raise RuntimeError("diagnostic pilots did not use fixed binaries and fresh process identities")
        result["status"] = "DIAGNOSIS_COMPLETE_ONLY"
        return 0
    finally:
        result["elapsed_s"] = time.monotonic() - started
        name = "idle-reader-comparison.json" if args.scenario == "idle" else "active-reader-comparison.json"
        write_json(args.evidence_dir / name, result)
        print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--toolchain", default="1.85.0")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--scenario", choices=("idle", "stream-large"), default="idle")
    parser.add_argument("--reader", choices=("psutil", "combined", "counter-check"))
    parser.add_argument("--library", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin" or not args.evidence_dir.is_absolute() or args.evidence_dir.exists():
        raise ValueError("fresh absolute Mac diagnostic directory required")
    if not args.cargo.is_absolute() or not args.cargo.is_file():
        raise ValueError("an explicit absolute Cargo executable is required")
    if bool(args.reader) != bool(args.library) or (args.library and not args.library.is_file()):
        raise ValueError("worker reader requires its compiled native library")
    if args.reader == "counter-check" and args.scenario == "idle":
        raise ValueError("counter comparison requires a streaming workload")
    protocol = read_json(PROTOCOL)
    return worker(args, protocol) if args.reader else compare(args, protocol)


if __name__ == "__main__":
    sys.exit(main())
