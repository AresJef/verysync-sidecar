"""Build a test consumer of an independently unpacked frozen upgrade crate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def extract(args):
    identity = json.loads(args.identity.read_text(encoding="utf-8"))
    if sha256(args.crate) != identity["candidate_crate_sha256"]:
        raise ValueError("wrong candidate crate SHA-256")
    if args.crate.stat().st_size != identity["candidate_crate_bytes"]:
        raise ValueError("wrong candidate crate size")
    current = subprocess.check_output(
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"], text=True, timeout=20
    ).splitlines()
    if current != [identity["source"], identity["tree"]]:
        raise ValueError("wrong candidate checkout")
    if sha256(Path("Cargo.lock")) != identity["locked_source_dependencies_sha256"]:
        raise ValueError("wrong candidate source lockfile")
    args.work.mkdir(mode=0o700)
    with tarfile.open(args.crate, "r:gz") as archive:
        archive.extractall(args.work, filter="data")
    package = args.work / f'verysync-sidecar-{identity["version"]}'
    info = json.loads((package / ".cargo_vcs_info.json").read_text(encoding="utf-8"))["git"]
    if info["sha1"] != identity["source"] or info.get("dirty", False):
        raise ValueError("unexpected source identity in the crate")
    return identity, package


def prepare(args):
    identity, package = extract(args)
    manifest = tomllib.loads((package / "Cargo.toml").read_text(encoding="utf-8"))
    if manifest["package"]["version"] != identity["version"]:
        raise ValueError("wrong candidate version")
    consumer = args.work / "consumer"
    testroot = consumer / "tests"
    testroot.mkdir(parents=True)
    test_files = ["upgrade_engine.rs", "upgrade_receipt_contract.rs"]
    if args.sdk_completion:
        test_files.extend((
            "authentication_engine.rs", "configuration_engine.rs", "devices.rs", "engine_control.rs", "events_contract.rs",
            "file_history_engine.rs", "file_mutation_engine.rs", "file_transfer_engine.rs",
            "local_sync_advanced_engine.rs", "local_sync_engine.rs", "local_sync_runtime_engine.rs", "managed_instance.rs",
            "invitations.rs",
            "p2p_three_nodes.rs",
            "sync_observation.rs", "transport_contract.rs",
        ))
    for name in test_files:
        shutil.copyfile(package / "tests" / name, testroot / name)
    shutil.copytree(package / "tests/common", testroot / "common")
    fixture_sources = {}
    if args.sdk_completion:
        shutil.copytree(package / "tests/fixtures", testroot / "fixtures")
        shutil.copytree(package / "scripts", consumer / "scripts")
        shutil.copytree(package / "releases", consumer / "releases")
        # The test-only device event witness also compiles this timestamp parser.
        # The tested library remains the independently unpacked dependency.
        name = "src/timestamps.rs"
        fixture_source = consumer / name
        fixture_source.parent.mkdir()
        shutil.copyfile(package / name, fixture_source)
        fixture_sources[name] = sha256(fixture_source)
    else:
        (consumer / "scripts").mkdir()
        shutil.copyfile(package / "scripts/prepare-test-engine.py", consumer / "scripts/prepare-test-engine.py")
    extra_dependencies = ""
    feature = ""
    if args.sdk_completion:
        feature = ('default = ["tls"]\n'
                   'tls = ["verysync-sidecar/tls"]\n'
                   'download = ["verysync-sidecar/download"]\n')
        extra_dependencies = """bzip2 = "0.6.1"
dunce = "1.0.5"
flate2 = { version = "1.1.11", default-features = false, features = ["miniz_oxide"] }
getrandom = "0.4.3"
jiff = { version = "=0.2.38", default-features = false, features = ["std"] }
libc = "=0.2.186"
lz4_flex = "0.13.0"
lzma-rust2 = { version = "=0.21.0", default-features = false, features = ["std", "xz"] }
rawzip = "0.5.2"
reqwest = { version = "0.13.5", default-features = false, features = ["json", "stream"] }
serde = { version = "1.0.229", features = ["derive"] }
snap = "1.1.1"
tar = { version = "0.4.46", default-features = false }
"""
    (consumer / "Cargo.toml").write_text(
        f"""[package]
name = "verysync-upgrade-receipt-consumer"
version = "0.0.0"
edition = "2021"
resolver = "3"
rust-version = "1.85"

[features]
engine-tests = []
{feature}
[dependencies]
verysync-sidecar = {{path = "../{package.name}", version = "={identity['version']}"}}
fs2 = "0.4.3"
rmpv = "1.3.1"
serde_json = "1.0.154"
sha2 = "0.10.9"
tempfile = "3.27.0"
tokio = {{version = "1.54.1", features = ["rt-multi-thread", "macros", "net", "io-util", "time"]}}
url = "2.5.9"
{extra_dependencies}
[target.'cfg(windows)'.dependencies]
windows-sys = {{ version = "0.61.2", features = ["Win32_Foundation", "Win32_Security", "Win32_Storage_FileSystem", "Win32_System_JobObjects", "Win32_System_Threading", "Win32_System_Pipes", "Win32_System_Diagnostics_ToolHelp"] }}
""",
        encoding="utf-8",
    )
    subprocess.run(["cargo", "+" + args.toolchain, "generate-lockfile", "--offline"],
                   cwd=consumer, timeout=60, check=True)
    print(json.dumps({
        "source": identity["source"],
        "tree": identity["tree"],
        "crate_sha256": identity["candidate_crate_sha256"],
        "consumer_lock_sha256": sha256(consumer / "Cargo.lock"),
        "unpacked_crate_lock_sha256": sha256(package / "Cargo.lock"),
        "native_test_source_sha256": sha256(testroot / "common/upgrade_receipt_native.rs"),
        "consumer_test_sources_sha256": {name: sha256(testroot / name) for name in test_files},
        "consumer_fixture_sources_sha256": fixture_sources,
        "consumer_uses_separately_unpacked_package": True,
    }, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--crate", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--sdk-completion", action="store_true",
                        help="include the additional public workflows for SDK completion")
    prepare(parser.parse_args())
