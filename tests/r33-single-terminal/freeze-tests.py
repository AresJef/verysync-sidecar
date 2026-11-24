"""Freeze the synthetic acceptance source and verify a fresh private extraction."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


def digest(value):
    return hashlib.sha256(value).hexdigest()


def pack(source, target, private):
    modules = sorted(path for path in source.rglob("*.py") if path.is_file() and not path.is_symlink())
    with ZipFile(target, "x") as archive:
        for path in modules:
            member = ZipInfo(path.relative_to(source).as_posix())
            member.compress_type = ZIP_DEFLATED
            archive.writestr(member, path.read_bytes())
    proof = {}
    with ZipFile(target) as archive:
        for member in archive.namelist():
            relative = PurePosixPath(member)
            if relative.is_absolute() or ".." in relative.parts or member in proof:
                raise ValueError("The synthetic source bundle contains an unexpected path.")
            received = archive.read(member)
            proof[member] = digest(received)
            assert proof[member] == digest((source/member).read_bytes())
            destination = private/member
            destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with destination.open("xb") as handle:
                handle.write(received)
    print("R33_SINGLE_FREEZE "+json.dumps({"archive_sha256":digest(target.read_bytes()),
          "source_files":len(proof),"runtime":{p:sha for p,sha in proof.items()
                                                if p.startswith("runtime-next/")}},sort_keys=True))


if __name__=="__main__":
    pack(*map(Path,sys.argv[1:]))

