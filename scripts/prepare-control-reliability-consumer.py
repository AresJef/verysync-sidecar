"""Compile an independent example consumer using the actual candidate archive."""
import argparse
from hashlib import file_digest
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib


def read_git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True, timeout=20).strip()


def checksum(path):
    with path.open("rb") as source:
        return file_digest(source, "sha256").hexdigest()


def checked(command, cwd, log):
    with log.open("xb") as output:
        exit_status = subprocess.run(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                     timeout=900, check=False).returncode
    if exit_status:
        print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]))
        raise SystemExit(exit_status)


def prepare(args):
    source = args.source.resolve(strict=True)
    root = args.work.resolve()
    root.mkdir(mode=0o700)
    proof = args.evidence.resolve()
    proof.mkdir(mode=0o700, parents=True)
    identity = read_git(source, "rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    if read_git(source, "status", "--porcelain"):
        raise ValueError("build the external consumer from a clean candidate checkout")
    manifest = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
    package = manifest["package"]
    crate_name, version = package["name"], package["version"]
    if crate_name != "verysync-sidecar":
        raise ValueError("unexpected candidate crate")
    cargo_path = args.cargo or shutil.which("cargo")
    if not cargo_path:
        raise ValueError("Cargo was not located")
    cargo = [str(Path(cargo_path).absolute()), "+" + args.toolchain]
    source_record = {
        "source": identity[0],
        "tree": identity[1],
        "version": version,
        "locked_source_dependencies_sha256": checksum(source / "Cargo.lock"),
        "example_source_sha256": checksum(source / "examples/gui_listener_recovery.rs"),
    }
    if args.candidate is None:
        packed = root / "package-target"
        checked([*cargo, "package", "--locked", "--offline", "--target-dir", str(packed)],
                source, proof / "package.log")
        archive = packed / "package" / f"{crate_name}-{version}.crate"
    else:
        archive = args.candidate.resolve(strict=True)
    package_record = {
        **source_record,
        "candidate_crate_sha256": checksum(archive),
        "candidate_crate_bytes": archive.stat().st_size,
    }
    if args.candidate_identity is not None:
        frozen = json.loads(args.candidate_identity.read_text(encoding="utf-8"))
        if frozen != package_record:
            raise ValueError("candidate artifact does not match the frozen package and checkout")
    if args.package_only:
        shutil.copyfile(archive, proof / "candidate.crate")
        (proof / "package.json").write_text(json.dumps(package_record, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(package_record))
        return

    unpacked = root / "unpacked"
    unpacked.mkdir()
    with tarfile.open(archive, "r:gz") as package_file:
        package_file.extractall(unpacked, filter="data")
    candidate = unpacked / f"{crate_name}-{version}"
    stamp = json.loads((candidate / ".cargo_vcs_info.json").read_text(encoding="utf-8"))["git"]
    if stamp["sha1"] != identity[0] or stamp.get("dirty", False):
        raise ValueError("external crate archive identifies a different source")
    fixture = root / "consumer"
    (fixture / "src").mkdir(parents=True)
    (fixture / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (fixture / "examples").mkdir()
    source_example = candidate / "examples/gui_listener_recovery.rs"
    if checksum(source_example) != source_record["example_source_sha256"]:
        raise ValueError("packaged example differs from the candidate source")
    external_example = fixture / "examples/gui_listener_recovery.rs"
    shutil.copyfile(source_example, external_example)
    candidate_path = json.dumps(str(candidate), ensure_ascii=False)
    external_manifest = f'''[package]
name = "listener-recovery-candidate-consumer"
version = "0.0.0"
edition = "2021"
rust-version = "1.85"
resolver = "3"

[dependencies]
verysync-sidecar = {{ path = {candidate_path}, version = "={version}" }}
serde = {{ version = "1.0.229", features = ["derive"] }}
serde_json = "1.0.154"
tempfile = "3.27.0"
tokio = {{ version = "1.54.1", features = ["macros", "rt-multi-thread"] }}
'''
    (fixture / "Cargo.toml").write_text(external_manifest, encoding="utf-8")
    consumer_target = root / "consumer-target"
    checked([*cargo, "generate-lockfile", "--offline"], fixture, proof / "consumer-lock.log")
    checked([*cargo, "build", "--locked", "--offline", "--target-dir", str(consumer_target),
             "--example", "gui_listener_recovery"], fixture, proof / "consumer-build.log")
    executable = (consumer_target / "debug" / "examples" /
                  ("gui_listener_recovery.exe" if os.name == "nt" else "gui_listener_recovery"))
    result = {
        **package_record,
        "consumer_lock_sha256": checksum(fixture / "Cargo.lock"),
        "example_executable_sha256": checksum(executable),
        "consumer_uses_independently_unpacked_candidate": True,
        "used_shared_candidate_archive": args.candidate is not None,
    }
    (proof / "build.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    env_path = executable.absolute().as_posix()
    if "\n" in env_path or "\r" in env_path:
        raise ValueError("external example path contains an environment separator")
    with args.github_env.open("a", encoding="utf-8") as output:
        output.write(f"VERYSYNC_TEST_RECOVERY_EXAMPLE={env_path}\n")
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    parser.add_argument("--package-only", action="store_true")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--candidate-identity", type=Path)
    parser.add_argument("--cargo")
    parser.add_argument("--toolchain", default="1.85.0")
    args = parser.parse_args()
    if (args.candidate is None) != (args.candidate_identity is None):
        parser.error("an external candidate requires its archive and recorded identity")
    if args.package_only and args.candidate is not None:
        parser.error("packing a candidate requires the clean source checkout")
    if not args.package_only and args.github_env is None:
        parser.error("the compiled consumer requires a private environment output")
    prepare(args)
