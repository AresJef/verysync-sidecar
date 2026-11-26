"""Record the crate rebuilt from the clean tree used by the Intel workload."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

archive, source, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
with tarfile.open(archive, "r:gz") as crate:
    prefix = "verysync-sidecar-0.1.1/"
    vcs = json.load(crate.extractfile(prefix + ".cargo_vcs_info.json"))
    if vcs["git"]["sha1"] != source or vcs["git"].get("dirty", False):
        raise ValueError("rebuilt crate differs from the clean workload source")
    evidence_files = [*Path("src").rglob("*.rs"), Path("Cargo.lock")]
    for relative in evidence_files:
        payload = crate.extractfile(prefix + relative.as_posix())
        if payload is None or payload.read() != relative.read_bytes():
            raise ValueError(f"rebuilt crate differs at {relative}")
with output.open("x") as record:
    json.dump({"commit": source, "crate_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
               "crate_bytes": archive.stat().st_size, "checked_members": len(evidence_files)}, record, indent=2)
    record.write("\n")
