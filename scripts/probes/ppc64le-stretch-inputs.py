"""Select and verify only the archived packages for the PPC64LE guest."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import lzma
from pathlib import Path
import re
import subprocess
import sys

archive = "https://archive.debian.org/debian/"
indices = {
    "stretch": (6899708, "2c8b59b02cd5be27834cf9df234ab6ae07d124f25d629fd2414c9dc2881345ed"),
    "buster": (7700664, "1491e0e6ed6e1556bf6d5e2ef8d81f345ed9ab25af1c7d830b012319adbea55e"),
}
packages = {
    "stretch": {"linux-image-4.9.0-13-powerpc64le", "busybox-static", "ca-certificates"},
    "buster": {"libc6", "libc6-dev", "libgcc1", "libatomic1", "linux-libc-dev"},
}
work = Path(sys.argv[1])
dest = work / "packages"
dest.mkdir(mode=0o700)

def fetch(relative, destination, expected_size, expected_sha):
    subprocess.run(("curl", "--proto", "=https", "--fail", "--silent", "--show-error",
                    "--connect-timeout", "10", "--max-time", "65", "--retry", "1",
                    "--max-filesize", str(expected_size), "--output", str(destination),
                    archive + relative), check=True)
    assert destination.stat().st_size == expected_size, destination.name
    assert sha256(destination.read_bytes()).hexdigest() == expected_sha, destination.name

def catalog(suite):
    index = work / f"{suite}-ppc64el-verified-index.xz"
    fetch(f"dists/{suite}/main/binary-ppc64el/Packages.xz", index, *indices[suite])
    data = lzma.decompress(index.read_bytes()).decode()
    chosen = {}
    for stanza in data.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in stanza.splitlines()
                      if ": " in line and not line[:1].isspace())
        name = fields.get("Package")
        if name not in packages[suite]:
            continue
        assert name not in chosen
        assert fields["Architecture"] in {"all", "ppc64el"}
        assert re.fullmatch(r"[0-9a-f]{64}", fields["SHA256"])
        assert re.fullmatch(r"pool/main/[A-Za-z0-9_+./~-]+\.deb", fields["Filename"])
        assert ".." not in Path(fields["Filename"]).parts
        chosen[name] = {
            "package": name, "version": fields["Version"], "filename": fields["Filename"],
            "size": int(fields["Size"]), "sha256": fields["SHA256"],
        }
        assert 0 < chosen[name]["size"] <= 64 * 1024 * 1024
    assert chosen.keys() == packages[suite], (suite, sorted(chosen))
    return list(chosen.values())

with ThreadPoolExecutor(max_workers=2) as pool:
    manifest = dict(zip(indices, pool.map(catalog, indices), strict=True))
def obtain(item):
    suite, row = item
    out = dest / f"{suite}-{row['package']}.deb"
    fetch(row["filename"], out, row["size"], row["sha256"])

wanted = [(suite, row) for suite, entries in manifest.items() for row in entries]
with ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(obtain, wanted))
original = manifest
output = Path("scripts/linux-minimum-boot-ppc64le-packages.json")
output.write_text(json.dumps(original, indent=2) + "\n")
(work / "authenticated-ppc64le-inputs.json").write_text(
    json.dumps({"pinned_indices": indices, "packages": original}, indent=2) + "\n")
print(json.dumps({"authenticated_ppc64le_inputs": original}, sort_keys=True))
