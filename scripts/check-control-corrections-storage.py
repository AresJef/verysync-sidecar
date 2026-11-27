#!/usr/bin/env python3
"""Verify the packaged recovery example's storage order using isolated processes."""

import argparse
from contextlib import contextmanager
from difflib import unified_diff
from hashlib import file_digest, sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time


EXAMPLE = "gui_listener_recovery"
PROBE = "section271_storage_probe"
DEVICE = "-".join(["AAAAAAA"] * 8)
PEER = "B" + DEVICE[1:]
API_KEY = "section271-synthetic-control-key"
OLD_ADDRESS = "127.0.0.1:42101"
NEW_ADDRESS = "127.0.0.1:42102"
LOOPBACK_READS = {
    "/rest/system/version",
    "/rest/system/status",
    "/rest/config",
    "/rest/config/gui",
}
WAIT = 20


TEST_ONLY_HELPER = r'''
// Instrumentation belongs only to the private executable built by the test.
struct TestStorageCompletion(PathBuf);

impl Drop for TestStorageCompletion {
    fn drop(&mut self) {
        let _ = fs::write(self.0.join("test-old-worker-done"), b"done");
    }
}

fn test_storage_before_replace(
    directory: &Path,
    bytes: &[u8],
    initial: bool,
) -> io::Result<Option<TestStorageCompletion>> {
    if initial {
        return Ok(None);
    }
    let receipt: Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if directory.join("test-deny-final").is_file()
        && receipt["submission"]["state"] == "acknowledged"
    {
        fs::write(directory.join("test-final-storage-error"), b"before-replace")?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "test-only final replacement error"));
    }
    if directory.join("test-gate-old").is_file()
        && receipt["intent"]["progress"]["pause_request"]["state"] == "possibly_submitted"
    {
        fs::copy(directory.join(RECEIPT_NAME), directory.join("test-prior-receipt"))?;
        fs::write(directory.join("test-old-worker-ready"), b"ready")?;
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !directory.join("test-release-old").is_file() {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "test-only gate was never released"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        return Ok(Some(TestStorageCompletion(directory.to_path_buf())));
    }
    Ok(None)
}

'''


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def digest(path):
    with path.open("rb") as source:
        return file_digest(source, "sha256").hexdigest()


def instrument(text):
    candidates = (
        (
            "            let temporary = stage_file(&self.directory, &bytes)?;\n",
            "            let _test_storage_done = test_storage_before_replace(&self.directory, &bytes, initial)?;\n",
            "journal-worker-before-commit-lock",
        ),
        (
            "    temporary.as_file().sync_all()?;\n    let destination = directory.join(name);\n",
            "    let _test_storage_done = if name == RECEIPT_NAME {\n"
            "        test_storage_before_replace(directory, bytes, initial)?\n"
            "    } else { None };\n",
            "rc6-before-replace",
        ),
    )
    for anchor, injection, name in candidates:
        if text.count(anchor) != 1:
            continue
        insertion = anchor.splitlines(keepends=True)[0]
        updated = text.replace(anchor, insertion + injection + anchor[len(insertion):], 1)
        return updated + TEST_ONLY_HELPER, name
    raise ValueError("the archived example no longer has a recognized pre-commit instrumentation anchor")


def prepare_probe(args):
    work = args.consumer_work.resolve(strict=True)
    identity = json.loads(args.consumer_build.read_text(encoding="utf-8"))
    require(
        identity["candidate_crate_sha256"] == digest(args.crate)
        and identity["candidate_crate_bytes"] == args.crate.stat().st_size
        and identity["consumer_uses_independently_unpacked_candidate"]
        and identity["used_shared_candidate_archive"],
        "the provided consumer did not build from this frozen archive",
    )
    unpacked = work / "unpacked" / f'verysync-sidecar-{identity["version"]}'
    stamp = json.loads((unpacked / ".cargo_vcs_info.json").read_text(encoding="utf-8"))["git"]
    require(stamp["sha1"] == identity["source"] and not stamp.get("dirty"), "wrong archive source")
    fixture = work / "consumer"
    target = work / "consumer-target"
    suffix = ".exe" if os.name == "nt" else ""
    executables = target / "debug" / "examples"
    original_executable = executables / (EXAMPLE + suffix)
    require(
        digest(original_executable) == identity["example_executables_sha256"][EXAMPLE],
        "the unmodified recovery executable no longer matches its recorded package build",
    )
    original = unpacked / "examples" / (EXAMPLE + ".rs")
    equivalent = fixture / "examples" / original.name
    require(
        digest(original) == digest(equivalent) == identity["example_sources_sha256"][EXAMPLE],
        "the package example source differs from the recorded example in the independent build",
    )
    text = original.read_text(encoding="utf-8")
    modified, anchor = instrument(text)
    test_patch = args.output / "test-only-storage-instrumentation.patch"
    test_patch.write_text(
        "".join(unified_diff(text.splitlines(True), modified.splitlines(True),
                             fromfile="a/examples/gui_listener_recovery.rs",
                             tofile="b/examples/gui_listener_recovery.rs")),
        encoding="utf-8",
        newline="\n",
    )
    probe_source = fixture / "examples" / (PROBE + ".rs")
    probe_code = modified.encode()
    with probe_source.open("xb") as file:
        file.write(probe_code)
    try:
        cargo = args.cargo or shutil.which("cargo")
        with (args.output / "instrumented-build.log").open("xb") as log:
            result = subprocess.run(
                [
                    cargo, "+" + args.toolchain, "build", "--locked", "--offline", "--example",
                    PROBE, "--target-dir", str(target),
                ],
                cwd=fixture,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=900,
                check=False,
            )
        require(result.returncode == 0, "test-only build failed; see instrumented-build.log")
    finally:
        probe_source.unlink()
    probe = executables / (PROBE + suffix)
    evidence = {
        "source_commit": identity["source"],
        "crate_sha256": identity["candidate_crate_sha256"],
        "packaged_example_source_sha256": digest(original),
        "unmodified_recovery_executable_sha256": digest(original_executable),
        "probe_source_sha256": sha256(probe_code).hexdigest(),
        "probe_executable_sha256": digest(probe),
        "instrumentation_patch_sha256": digest(test_patch),
        "instrumentation_anchor": anchor,
    }
    (args.output / "storage-binaries.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n",
    )
    return original_executable, probe


class Origin:
    def __init__(self, hold=None):
        self.hold = hold
        self.requests = []
        self.address = OLD_ADDRESS
        self.entered = threading.Event()
        self.release = threading.Event()

    def wait_if_selected(self, method, path):
        if (method, path) == self.hold and not self.entered.is_set():
            self.entered.set()
            self.release.wait(WAIT)


@contextmanager
def origin(hold=None):
    fixture = Origin(hold)
    os_name = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    machine = platform.machine().lower()
    architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64",
                    "amd64": "amd64"}.get(machine, machine)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, status, value):
            raw = json.dumps(value).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            fixture.requests.append(("GET", self.path))
            if self.headers.get("X-API-Key") != API_KEY:
                return self.respond(401, {})
            if self.path == "/rest/system/version":
                value = {"version": "v2.33.2", "os": os_name, "arch": architecture}
            elif self.path == "/rest/system/status":
                value = {"myID": DEVICE}
            elif self.path == "/rest/config":
                value = {
                    "devices": [{"deviceID": PEER, "name": "Synthetic peer", "addresses": [],
                                 "compression": "metadata", "paused": False}],
                    "folders": [],
                }
            elif self.path == "/rest/config/gui":
                fixture.wait_if_selected("GET", self.path)
                value = {
                    "enabled": True, "authMode": "static", "user": "", "password": "",
                    "apiKey": API_KEY, "address": fixture.address,
                    "useTLS": False, "unixSocketPermissions": "",
                }
            else:
                return self.respond(404, {})
            self.respond(200, value)

        def do_PATCH(self):
            fixture.requests.append(("PATCH", self.path))
            if self.headers.get("X-API-Key") != API_KEY:
                return self.respond(401, {})
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path != "/rest/config/gui" or data != {"address": NEW_ADDRESS}:
                return self.respond(400, {})
            fixture.address = data["address"]
            fixture.wait_if_selected("PATCH", self.path)
            self.respond(200, {})

        def do_DELETE(self):
            fixture.requests.append(("DELETE", self.path))
            self.respond(500, {})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    connection = {
        "endpoint": f"http://127.0.0.1:{server.server_port}",
        "api_key": API_KEY,
        "expected_device_id": DEVICE,
        "timeout_ms": 5000,
    }
    try:
        yield fixture, connection
    finally:
        fixture.release.set()
        server.shutdown()
        server.server_close()
        worker.join(WAIT)
        require(not worker.is_alive(), "loopback fixture did not exit")


def verify_redaction(contents):
    require(API_KEY.encode() not in contents, "synthetic management credential was exposed")


def child_environment():
    return {key: value for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}


@contextmanager
def running(executable, command, directory, data):
    stdout = directory / "probe.stdout"
    stderr = directory / "probe.stderr"
    with stdout.open("xb") as output, stderr.open("xb") as errors:
        child = subprocess.Popen(
            [executable, command, directory],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=errors,
            env=child_environment(),
        )
    assert child.stdin is not None
    try:
        child.stdin.write(json.dumps(data).encode())
        child.stdin.close()
        yield child, stdout, stderr
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=WAIT)


def until(condition, explanation):
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.015)
    raise AssertionError(explanation)


def read_result(stdout):
    value = stdout.read_bytes()
    if not value.endswith(b"\n"):
        return None
    return json.loads(value)


def process_result(child, stdout, stderr):
    status = child.wait(timeout=WAIT)
    raw_stdout = stdout.read_bytes()
    raw_stderr = stderr.read_bytes()
    verify_redaction(raw_stdout + raw_stderr)
    require(raw_stdout.endswith(b"\n"), "example did not print a complete JSON result")
    return {
        "pid": child.pid,
        "exit_code": status,
        "stdout": raw_stdout.decode(),
        "stderr": raw_stderr.decode(),
        "json": json.loads(raw_stdout),
    }


def disk_receipt(directory, name="receipt.json"):
    raw = (directory / name).read_bytes()
    verify_redaction(raw)
    value = json.loads(raw)
    progress = value["intent"].get("progress")
    return {
        "sha256": sha256(raw).hexdigest(),
        "operation_id": value["operation_id"],
        "submission": value["submission"],
        "response_status": value["response_status"],
        "pause": progress["pause_request"] if progress else None,
        "elapsed_millis": value["elapsed_millis"],
    }


def recover(executable, command, directory, connection, fixture):
    start = len(fixture.requests)
    with subprocess.Popen(
        [executable, command, directory],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment(),
    ) as child:
        try:
            stdout, stderr = child.communicate(json.dumps(connection).encode(), timeout=WAIT)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            raise
    verify_redaction(stdout + stderr)
    requests = fixture.requests[start:]
    require(
        child.returncode == 0 and len(requests) == 6
        and all(method == "GET" and path in LOOPBACK_READS for method, path in requests),
        f"the second process did not perform precisely six allowed reads: {child.returncode}, {requests}",
    )
    return {
        "pid": child.pid,
        "exit_code": child.returncode,
        "stdout": stdout.decode(),
        "stderr": stderr.decode(),
        "json": json.loads(stdout),
        "requests": requests,
        "modifications": 0,
    }


def write_counts(requests):
    return {method: sum(current == method for current, _ in requests)
            for method in ("PATCH", "DELETE")}


def delayed_checkpoint(directory, app, probe):
    (directory / "test-gate-old").touch()
    with origin() as (fixture, connection):
        request = {**connection, "peer_id": PEER, "disconnect_timeout_ms": 2000}
        with running(probe, "remove-device", directory, request) as (child, stdout, stderr):
            try:
                until(lambda: (directory / "test-old-worker-ready").is_file(),
                      "the original pause checkpoint never entered the filesystem worker")
                first_disk = disk_receipt(directory, "test-prior-receipt")
                require(first_disk["submission"]["state"] == "prepared", "the initial intent was not preserved")
                public_before_release = until(
                    lambda: read_result(stdout),
                    "the final result was not emitted while the older worker was blocked",
                )
                final_disk = disk_receipt(directory)
                require(
                    public_before_release["final_receipt_saved"] is True
                    and public_before_release["submission"] == "not_submitted"
                    and final_disk["submission"]["state"] == final_disk["pause"]["state"] == "not_submitted"
                    and final_disk["elapsed_millis"] >= request["disconnect_timeout_ms"]
                    and not (directory / "test-old-worker-done").exists()
                    and child.poll() is None,
                    "the final receipt was not committed with the earlier storage worker still blocked",
                )
            finally:
                (directory / "test-release-old").touch()
            until(lambda: (directory / "test-old-worker-done").is_file(), "the older filesystem worker never finished")
            original = process_result(child, stdout, stderr)
        reopened_before_reads = disk_receipt(directory)
        reopened = recover(app, "observe-device", directory, connection, fixture)
        writes = write_counts(fixture.requests)
        identity = first_disk["operation_id"]
        linked = all(
            info["operation_id"] == identity for info in
            (final_disk, reopened_before_reads, original["json"], reopened["json"])
        )
        require(
            linked and writes == {"PATCH": 0, "DELETE": 0} and reopened["pid"] != original["pid"],
            "operation identity, process separation or zero-write evidence changed",
        )
        passed = (
            original["exit_code"] == 1
            and reopened_before_reads == final_disk
            and reopened_before_reads["submission"]["state"] == "not_submitted"
            and reopened_before_reads["pause"]["state"] == "not_submitted"
            and reopened["json"]["submission"] == "not_submitted"
            and reopened["json"]["device_removal_progress"]["pause_request"]["state"] == "not_submitted"
        )
        return {
            "case": "A1_late_pause_checkpoint",
            "passed": passed,
            "evidence": {
                "initial_disk": first_disk,
                "operation_deadline_ms": request["disconnect_timeout_ms"],
                "final_summary_before_release": public_before_release,
                "final_disk_before_release": final_disk,
                "older_worker_finished_after_release": True,
                "disk_after_worker_finished": reopened_before_reads,
                "initiating_process": original,
                "separately_started_recovery_process": reopened,
                "write_counts": writes,
                "all_requests": fixture.requests,
            },
        }


def final_store_denied(directory, app, probe):
    (directory / "test-deny-final").touch()
    with origin(("PATCH", "/rest/config/gui")) as (fixture, connection):
        with running(probe, "submit", directory, {**connection, "bind": NEW_ADDRESS}) as (child, stdout, stderr):
            require(fixture.entered.wait(WAIT), "the synthetic origin did not receive the listener PATCH")
            earlier = disk_receipt(directory)
            fixture.release.set()
            original = process_result(child, stdout, stderr)
        after = disk_receipt(directory)
        reopened = recover(app, "observe", directory, connection, fixture)
        writes = write_counts(fixture.requests)
        passed = (
            (directory / "test-final-storage-error").read_bytes() == b"before-replace"
            and original["exit_code"] == 1
            and original["json"]["failure"] == "receipt_storage"
            and not original["json"].get("final_receipt_saved", False)
            and original["json"]["submission"] == "acknowledged"
            and earlier == after and after["submission"]["state"] == "possibly_submitted"
            and original["json"]["operation_id"] == reopened["json"]["operation_id"] == after["operation_id"]
            and reopened["json"]["submission"] == "possibly_submitted"
            and reopened["json"]["requested_fields_match"]
            and writes == {"PATCH": 1, "DELETE": 0}
        )
        return {
            "case": "A2_final_storage_error",
            "passed": passed,
            "evidence": {
                "earlier_checkpoint": earlier, "disk_after_replacement_error": after,
                "initiating_process": original, "separately_started_recovery_process": reopened,
                "write_counts": writes, "all_requests": fixture.requests,
            },
        }


def existing_intent(directory, app):
    with origin() as (fixture, connection):
        with running(app, "submit", directory, {**connection, "bind": NEW_ADDRESS}) as (child, stdout, stderr):
            first = process_result(child, stdout, stderr)
        require(first["exit_code"] == 0, "first operation must create a complete valid receipt")
        before = disk_receipt(directory)
        stdout.unlink()
        stderr.unlink()
        start = len(fixture.requests)
        with running(app, "submit", directory, {**connection, "bind": OLD_ADDRESS}) as (child, stdout, stderr):
            refused = process_result(child, stdout, stderr)
        after = disk_receipt(directory)
        second_requests = fixture.requests[start:]
        second_writes = write_counts(second_requests)
        reopened = recover(app, "observe", directory, connection, fixture)
        passed = (
            refused["exit_code"] == 1
            and refused["json"]["failure"] == "receipt_storage"
            and refused["json"]["submission"] == "not_submitted"
            and refused["json"]["operation_id"] != first["json"]["operation_id"]
            and before == after
            and reopened["json"]["operation_id"] == first["json"]["operation_id"]
            and second_writes == {"PATCH": 0, "DELETE": 0}
        )
        return {
            "case": "A2_initial_no_overwrite",
            "passed": passed,
            "evidence": {
                "original_process": first, "disk_before_refused_operation": before,
                "second_process": refused, "disk_after_refused_operation": after,
                "separately_started_recovery_process": reopened,
                "second_process_requests": second_requests, "second_process_write_counts": second_writes,
            },
        }


def terminated(directory, app, dispatched):
    method = "PATCH" if dispatched else "GET"
    with origin((method, "/rest/config/gui")) as (fixture, connection):
        with running(app, "submit", directory, {**connection, "bind": NEW_ADDRESS}) as (child, stdout, stderr):
            require(fixture.entered.wait(WAIT), "the interrupted operation did not reach its selected boundary")
            before = disk_receipt(directory)
            child.kill()
            exit_status = child.wait(timeout=WAIT)
            raw_output = stdout.read_bytes() + stderr.read_bytes()
            verify_redaction(raw_output)
            require(not stdout.read_bytes(), "the killed process published a final receipt summary")
            fixture.release.set()
        original_requests = list(fixture.requests)
        reopened = recover(app, "observe", directory, connection, fixture)
        after = disk_receipt(directory)
        expected = "possibly_submitted" if dispatched else "prepared"
        passed = (
            exit_status != 0 and before == after and after["submission"]["state"] == expected
            and reopened["json"]["operation_id"] == after["operation_id"]
            and reopened["json"]["submission"] == expected
            and reopened["json"]["requested_fields_match"] is dispatched
            and write_counts(original_requests) == {"PATCH": int(dispatched), "DELETE": 0}
        )
        return {
            "case": "A2_process_exit_after_write" if dispatched else "A2_process_exit_before_write",
            "passed": passed,
            "evidence": {
                "terminated_process": {"pid": child.pid, "exit_code": exit_status, "stdout": "",
                                       "stderr": stderr.read_text(encoding="utf-8")},
                "disk_before_termination": before, "disk_after_recovery": after,
                "separately_started_recovery_process": reopened,
                "initiating_requests": original_requests,
                "initiating_write_counts": write_counts(original_requests),
            },
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer-work", type=Path, required=True)
    parser.add_argument("--consumer-build", type=Path, required=True)
    parser.add_argument("--crate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo")
    parser.add_argument("--toolchain", default="1.85.0")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True)
    app, probe = prepare_probe(args)
    cases = {
        "A1": lambda directory: delayed_checkpoint(directory, app, probe),
        "A2_final_storage_error": lambda directory: final_store_denied(directory, app, probe),
        "A2_initial_no_overwrite": lambda directory: existing_intent(directory, app),
        "A2_exit_before": lambda directory: terminated(directory, app, False),
        "A2_exit_after": lambda directory: terminated(directory, app, True),
    }
    overall = True
    with (args.output / "storage-results.jsonl").open("x", encoding="utf-8", newline="\n") as log:
        for name, run in cases.items():
            with tempfile.TemporaryDirectory(prefix="vss-control-storage-") as root:
                try:
                    receipt = run(Path(root))
                except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
                    receipt = {"case": name, "passed": False, "test_error": str(error)}
            receipt["private_case_directory_removed"] = not Path(root).exists()
            overall &= receipt["passed"] and receipt["private_case_directory_removed"]
            record = json.dumps(receipt, ensure_ascii=False)
            log.write(record + "\n")
            print(record, flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
