#!/usr/bin/env python3
"""Inspect one private native support ZIP; emit only bounded admission counts."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

DISABLED_FIELDS = ("trackerEnabled", "relaysEnabled", "natEnabled", "udpEnabled", "globalAnnounceEnabled", "localAnnounceEnabled")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_bundle(source, selected_kib):
    require(selected_kib in (32768, 65536), "unknown frozen admission setting")
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 64, "unbounded support entry count")
        require(sum(item.file_size for item in entries) <= 16 * 1024 * 1024, "unbounded support size")
        names = [item.filename for item in entries]
        require(len(set(names)) == len(names), "duplicate support entry")
        require(all(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts and "\\" not in name for name in names), "unsafe support name")
        require(all(item.file_size <= 4 * 1024 * 1024 for item in entries), "unbounded support member")
        require(archive.testzip() is None, "invalid support CRC")
        options = json.loads(archive.read("config.json.txt"))["options"]
        require(type(options["maxConcurrentIncomingRequestKiB"]) is int and options["maxConcurrentIncomingRequestKiB"] == selected_kib, "native cap differs")
        require(options["maxSendKbps"] == 1 and options["limitBandwidthInLan"] is True, "native LAN limiter differs")
        require(all(options[field] is False for field in DISABLED_FIELDS), "external discovery or transport enabled")
        require(json.loads(archive.read("version-platform.json.txt"))["version"] == "v2.33.2", "native version differs")
        profiles = [name for name in names if name.startswith("verysync-goroutine-") and name.endswith(".txt")]
        require(len(profiles) == 1, "one native goroutine snapshot required")
        text = archive.read(profiles[0]).decode("utf-8")
        require(re.match(r"goroutine profile: total \d+\n", text) is not None, "unknown native profile format")
        admitted = waiting = 0
        for stack in text.split("\n\n"):
            callback = "model.newLimitedRequestResponse.func1" in stack
            taker = "takeInner" in stack and "model.newLimitedRequestResponse" in stack
            if not (callback or taker):
                continue
            count = re.search(r"(?m)^(\d+) @", stack)
            require(count is not None, "missing native stack multiplicity")
            if callback:
                require("(*requestResponse).Wait" in stack, "callback is not waiting for completion")
                admitted += int(count.group(1))
            if taker:
                waiting += int(count.group(1))
        require(admitted * 131072 == selected_kib * 1024, "saturated admitted bytes differ from cap")
        require(waiting > 0, "no blocking demand observed")
        return {"selected_kib": selected_kib, "admitted_callback_count": admitted, "admitted_bytes": admitted * 131072, "block_bytes": 131072, "waiting_for_admission_count": waiting, "native_version_matches": True, "native_configuration_matches": True, "raw_support_contents_logged": False, "total_process_memory_bound_claimed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("selected_kib", type=int, choices=(32768, 65536))
    args = parser.parse_args()
    require(args.archive.is_file() and args.archive.stat().st_size <= 16 * 1024 * 1024, "missing or oversized private archive")
    result = inspect_bundle(args.archive, args.selected_kib)
    result["support_sha256"] = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
