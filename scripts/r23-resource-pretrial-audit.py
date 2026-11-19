#!/usr/bin/env python3
"""Read the published admission artifact from the exact failed macOS ARM64 job."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile


PREFIX = "vs-resource-v25-pretrial"
SOURCE = "0a6a4392c3fee3e83fbe0561a1f9357eeaf00ad2"
PROTOCOL = "ae970dbf8c54b30e44815277c39995984cc8a40f1587bfcf5c391bd621719d2e"
ORDER = ("idle", "stream-small", "stream-large", "many-small")
REASONS = {
    "batch too short",
    "insufficient measured or baseline observations",
    "sampling gap exceeded coverage limit",
    "boundary observation span insufficient",
    "metric read overhead exceeded limit",
}
VALUES = ("elapsed_ns", "samples", "max_sample_gap_ns",
          "boundary_overspan_fraction", "metric_read_fraction")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_record(archive, path):
    wanted = PurePosixPath(path).parts
    entries = [entry for entry in archive.infolist()
               if PurePosixPath(entry.filename).parts[-len(wanted):] == wanted]
    require(len(entries) == 1 and entries[0].file_size <= 128 * 1024,
            "Expected one bounded admission record")
    with archive.open(entries[0]) as stream:
        return json.load(stream)


def audit(metadata, archive_path):
    require(metadata["id"] == 14519654541
            and metadata["name"] == "frozen-resources-macos-arm64-standard-44507962811"
            and metadata["workflow_run"]["id"] == 44507962811
            and metadata["workflow_run"]["head_sha"] == SOURCE,
            "Different source artifact")
    payload = archive_path.read_bytes()
    require(len(payload) == metadata["size_in_bytes"] <= 1024 * 1024,
            "Unexpected archive size")
    require(metadata["digest"] == "sha256:" + hashlib.sha256(payload).hexdigest(),
            "Archive content differs from the published digest")
    with zipfile.ZipFile(archive_path) as archive:
        trial = read_record(archive, PREFIX + "/pretrial-result.json")
        require(trial["formal_sample"] is False
                and trial["protocol_sha256"] == PROTOCOL
                and trial["status"] == "PREPARATION_INSUFFICIENT",
                "Different frozen admission trial")
        expected = [(cycle, slot, scenario)
                    for cycle, order in enumerate((ORDER, tuple(reversed(ORDER))))
                    for slot, scenario in enumerate(order)]
        actual = [(a["cycle"], a["slot"], a["scenario"]) for a in trial["attempts"]]
        require(actual == expected, "Different scenario coverage or order")
        observed = []
        for attempt, (cycle, slot, scenario) in zip(trial["attempts"], expected):
            location = f"{PREFIX}/cycle-{cycle}-slot-{slot}-{scenario}/quality-result.json"
            quality = read_record(archive, location)
            status = quality["status"]
            reasons = quality["insufficient"]
            require(status == attempt["quality_status"] and status in {"VALID", "INSUFFICIENT"}
                    and not quality["errors"] and set(reasons) <= REASONS
                    and bool(reasons) == (status == "INSUFFICIENT"),
                    "Original quality fields disagree")
            observed.append({"cycle": cycle, "slot": slot, "scenario": scenario,
                             "status": status, "insufficient": reasons,
                             **{key: quality[key] for key in VALUES}})
        require(sum(row["status"] == "VALID" for row in observed) == 6
                and trial["readiness"]["complete_valid_orders"] == [],
                "Different admission result")
    return {"artifact": metadata["id"], "digest": metadata["digest"], "source": SOURCE,
            "protocol": PROTOCOL, "formal_samples": 0, "original_admission": observed}


if __name__ == "__main__":
    metadata_file, archive_file = (Path(arg) for arg in sys.argv[1:])
    print(json.dumps(audit(json.loads(metadata_file.read_text()), archive_file), allow_nan=False))
