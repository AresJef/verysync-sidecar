#!/usr/bin/env python3
"""Collect frozen complete resource cycles; raw attempts never replace groups."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix="owned-record-", delete=False) as file:
        json.dump(value, file, indent=2)
        file.write("\n"); file.flush(); os.fsync(file.fileno())
        temporary = Path(file.name)
    temporary.replace(path)


def metrics_module():
    spec = importlib.util.spec_from_file_location("resource_metrics", Path(__file__).with_name("measure-native-resources.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify_group(manifest, directory, protocol_hash, stage, metrics):
    protocol_path = directory / "frozen-protocol.json"
    if digest(protocol_path) != protocol_hash:
        raise ValueError("saved frozen protocol changed")
    protocol = json.loads(protocol_path.read_text())
    order = protocol[stage+"_orders"][manifest["cycle"]]
    if manifest["order"] != order or [x["scenario"] for x in manifest["slots"]] != order:
        raise ValueError("complete original-order coverage differs")
    identities, artifacts = [], set()
    for slot in manifest["slots"]:
        folder = directory / slot["directory"]
        if set(slot["sha256"]) != {"preparation-result.json", "samples.jsonl", "events.jsonl", "quality-result.json"}:
            raise ValueError("accepted group lacks immutable raw evidence")
        for filename, expected in slot["sha256"].items():
            if digest(folder / filename) != expected:
                raise ValueError("accepted raw record changed")
        report = json.loads((folder / "preparation-result.json").read_text())
        rows = [json.loads(x) for x in (folder / "samples.jsonl").read_text().splitlines()]
        if report["stage"] != stage or report.get("protocol_sha256") != protocol_hash:
            raise ValueError("accepted attempt role/configuration differs")
        if any(report["source"].get(key) != value for key, value in protocol["source_inputs"].items()):
            raise ValueError("accepted source dependency differs")
        if metrics.summarize(report, rows)["status"] != "VALID":
            raise ValueError("accepted attempt no longer validates")
        identities.extend((p["pid"], p["creation_time"]) for p in report["identities"])
        artifacts.add(bytes(report["events"][0]["controller_sha256"]).hex())
    if len(set(identities)) != len(identities) or len(artifacts) != 1:
        raise ValueError("fresh process or loaded-artifact coverage differs")
    return identities, artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=["formal", "independent", "all"], required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--toolchain", default="1.85.0")
    parser.add_argument("--deadline-unix", type=float)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    protocol = json.loads(args.protocol.read_text())
    protocol_hash = digest(args.protocol)
    if digest(__file__) != protocol["collector_sha256"]:
        raise ValueError("collector differs from frozen source")
    metrics = metrics_module()
    source = metrics.source_identity(args.cargo, args.toolchain)
    if any(source.get(key) != value for key, value in protocol["source_inputs"].items()):
        raise ValueError("measurement source differs; preserve old data and revalidate changed inputs")
    directory = args.evidence_dir
    if not directory.is_absolute():
        raise ValueError("absolute evidence directory required")
    if not args.resume:
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    state_path = directory / "collection-state.json"
    if args.resume:
        state = json.loads(state_path.read_text())
        if state["protocol_sha256"] != protocol_hash or state["stage"] != args.stage:
            raise ValueError("resume identity differs")
        if args.deadline_unix is not None and args.deadline_unix != state["deadline_unix"]:
            raise ValueError("resume cannot reset the original deadline")
    else:
        state = {"protocol_sha256": protocol_hash, "stage": args.stage, "start_unix": time.time(),
                 "deadline_unix": args.deadline_unix or time.time()+protocol["acquisition_window_s"],
                 "accepted": {}, "attempts": {}, "status": "INCOMPLETE", "source": source}
        save(directory / "frozen-protocol.json", protocol)
        save(state_path, state)
    # The live coordinator lease prevents a second collector from resuming the
    # same stage. Locks release with this exact process, including on failure.
    with (directory / "coordinator.lock").open("a+b") as lease:
        if os.name == "nt":
            import msvcrt
            lease.write(b"0"); lease.flush(); lease.seek(0)
            msvcrt.locking(lease.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.resume:
            psutil = metrics.dependency()
            for journal in directory.rglob("events.jsonl"):
                events = [json.loads(x) for x in journal.read_text().splitlines() if x.strip()]
                if events and events[0].get("kind") == "ready" and not any(x.get("kind") == "complete" for x in events):
                    try:
                        process = psutil.Process(events[0]["controller_pid"])
                        if os.path.samefile(process.exe(), events[0]["controller_executable"]):
                            raise RuntimeError("an unfinished owned controller is still alive; wait for its bounded cleanup")
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        pass
        if args.stage == "all":
            for stage in ["formal", "independent"]:
                child_dir = directory / stage
                command = [sys.executable, "-B", str(Path(__file__)), "--stage", stage,
                           "--protocol", str(directory / "frozen-protocol.json"),
                           "--evidence-dir", str(child_dir), "--cargo", str(args.cargo),
                           "--toolchain", args.toolchain, "--deadline-unix", str(state["deadline_unix"])]
                if args.resume and (child_dir / "collection-state.json").exists():
                    command.append("--resume")
                result = subprocess.run(command, check=False)
                state[stage] = result.returncode; save(state_path, state)
                if result.returncode:
                    return result.returncode
            phases = [json.loads((directory / stage / "collection-state.json").read_text()) for stage in ["formal", "independent"]]
            identities = [tuple(p) for phase in phases for p in phase["process_identities"]]
            artifacts = {h for phase in phases for h in phase["controller_artifact_sha256"]}
            if len(set(identities)) != len(identities) or len(artifacts) != 1:
                raise ValueError("independent collection reused processes or changed the loaded artifact")
            state["status"] = "COMPLETE"
            state["end_unix"] = time.time(); save(state_path, state)
            print(json.dumps({"stage": "all", "coverage": "COMPLETE", "resource_conclusion": "PENDING_REPORT", "directory": str(directory)}))
            return 0
        orders = protocol[args.stage+"_orders"]
        all_identities, all_artifacts = [], set()
        for index, order in enumerate(orders):
            key = str(index)
            if key in state["accepted"]:
                record = state["accepted"][key]
                path = directory / record["manifest"]
                if digest(path) != record["sha256"]:
                    raise ValueError("accepted group manifest changed")
                manifest = json.loads(path.read_text())
            else:
                manifest = None
                while state["attempts"].get(key, 0) < protocol["maximum_group_attempts"]:
                    if time.time()+protocol["estimated_complete_group_s"]+protocol["save_reserve_s"] > state["deadline_unix"]:
                        save(state_path, state); return 2
                    attempt = state["attempts"].get(key, 0)+1
                    state["attempts"][key] = attempt; save(state_path, state)
                    folder = directory / f"cycle-{index}-attempt-{attempt}"; folder.mkdir()
                    candidate = {"cycle": index, "attempt": attempt, "order": order, "slots": [], "start_unix": time.time()}
                    for slot, scenario in enumerate(order):
                        target = folder / f"slot-{slot}-{scenario}"
                        command = [sys.executable, "-B", str(Path(__file__).with_name("measure-native-resources.py")),
                                   "--stage", args.stage, "--protocol", str(directory / "frozen-protocol.json"),
                                   "--cargo", str(args.cargo), "--toolchain", args.toolchain,
                                   "--scenario", scenario, "--repeats", str(protocol["scenarios"][scenario]["repeats"]),
                                   "--interval-ms", str(protocol["interval_ms"]), "--evidence-dir", str(target)]
                        with (folder / f"slot-{slot}.console.log").open("wb") as log:
                            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
                        quality_path = target / "quality-result.json"
                        quality = json.loads(quality_path.read_text()) if quality_path.exists() else {"status": "ERROR"}
                        row = {"scenario": scenario, "directory": str(target.relative_to(directory)),
                               "exit_code": result.returncode, "quality": quality, "sha256": {}}
                        for filename in ["preparation-result.json", "samples.jsonl", "events.jsonl", "quality-result.json"]:
                            if (target / filename).exists(): row["sha256"][filename] = digest(target / filename)
                        candidate["slots"].append(row); save(folder / "attempt.json", candidate)
                        if quality["status"] == "ERROR" or result.returncode not in {0, 2}:
                            state["status"] = "ERROR"; save(state_path, state); return 1
                    candidate["end_unix"] = time.time()
                    valid = (all(x["quality"]["status"] == "VALID" and x["exit_code"] == 0 for x in candidate["slots"])
                             and candidate["end_unix"]-candidate["start_unix"] <= protocol["maximum_group_span_s"])
                    candidate["status"] = "VALID" if valid else "INSUFFICIENT"
                    save(folder / "attempt.json", candidate)
                    if valid:
                        verify_group(candidate, directory, protocol_hash, args.stage, metrics)
                        path = folder / "accepted-group.json"; save(path, candidate)
                        state["accepted"][key] = {"manifest": str(path.relative_to(directory)), "sha256": digest(path)}
                        save(state_path, state); manifest = candidate
                        break
                if manifest is None: return 2
            identities, artifacts = verify_group(manifest, directory, protocol_hash, args.stage, metrics)
            all_identities.extend(identities); all_artifacts.update(artifacts)
        if len(set(all_identities)) != len(all_identities) or len(all_artifacts) != 1:
            raise ValueError("accepted cycles lack fresh identity or artifact consistency")
        state.update(status="COMPLETE", end_unix=time.time(), process_identities=all_identities,
                     controller_artifact_sha256=list(all_artifacts))
        save(state_path, state)
        print(json.dumps({"stage": args.stage, "accepted_complete_cycles": len(orders), "coverage": "COMPLETE", "directory": str(directory)}))
        return 0


if __name__ == "__main__":
    sys.exit(main())
