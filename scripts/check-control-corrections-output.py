"""Run package-external control examples against disposable loopback fixtures."""

import argparse
from contextlib import ExitStack, contextmanager, suppress
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


OWN = "-".join(["AAAAAAA"] * 8)
PEER = "B" + OWN[1:]
KEY = "synthetic-section27-one-time-fixture-key"
OLD_ADDRESS = "127.0.0.1:42101"
NEW_ADDRESS = "127.0.0.1:42102"
GUI = "/rest/config/gui"
CONFIG = "/rest/config"
DEVICE = CONFIG + "/devices/" + PEER
CONNECTIONS = "/rest/system/connections"
FOLDERS = CONFIG + "/folders/"
BODY_DEADLINE_MS = 1500
FIXTURE_LIMIT = 15


class Fixture:
    def __init__(self, *, gui_reply=200, delete_reply=200, config_read=None,
                 prior_address=OLD_ADDRESS, failed_readback=False,
                 rejected_folder=None):
        self.address = prior_address
        self.gui_reply = gui_reply
        self.delete_reply = delete_reply
        self.config_read = config_read
        self.failed_readback = failed_readback
        self.rejected_folder = rejected_folder
        self.registered = True
        self.paused = False
        self.folders = {
            name: {"id": name, "label": "synthetic-original-label", "paused": False}
            for name in ("folder-a", "folder-b", "folder-c")
        }
        self.requests = []
        self.barrier = threading.Event()
        self.release = threading.Event()
        self.block_at = None
        self.lock = threading.Lock()

    def answer(self, role, method, route, request):
        with self.lock:
            action, data = self._answer(role, method, route, request)
            self.requests.append((role, method, route, action))
            return action, data

    def _answer(self, role, method, route, request):
        if method == "GET":
            if route == "/rest/system/version":
                return 200, {"version": "v2.33.2", "os": "darwin", "arch": "arm64"}
            if route == "/rest/system/status":
                return 200, {"myID": OWN}
            if route == GUI:
                if role == "readback" and self.failed_readback:
                    return 503, {}
                return 200, {
                    "enabled": True, "authMode": "static", "user": "",
                    "password": "", "apiKey": KEY, "address": self.address,
                    "useTLS": False, "unixSocketPermissions": "",
                }
            if route == CONFIG:
                rejected = (
                    self.config_read == "before"
                    or self.config_read == "post_delete" and not self.registered
                    or self.config_read == "after_pause" and self.paused
                )
                if role == "submit" and rejected:
                    return 403, {}
                device = {
                    "deviceID": PEER, "name": "synthetic-peer",
                    "addresses": [], "compression": "metadata", "paused": self.paused,
                }
                return 200, {"devices": [device] if self.registered else [], "folders": []}
            if route == CONNECTIONS:
                return 200, {"connections": {PEER: {"connected": not self.paused}}}
            if route.startswith(FOLDERS) and route[len(FOLDERS):] in self.folders:
                return 200, self.folders[route[len(FOLDERS):]].copy()
        if method == "PATCH" and route == GUI:
            if self.gui_reply in (200, "drop"):
                self.address = request["address"]
            return self.gui_reply, {}
        if method == "PATCH" and route == DEVICE and request == {"paused": True}:
            self.paused = True
            return 200, {}
        if method == "DELETE" and route == DEVICE:
            if self.delete_reply in (200, "drop"):
                self.registered = False
            return self.delete_reply, {}
        if method == "PATCH" and route.startswith(FOLDERS):
            folder = route[len(FOLDERS):]
            if folder == self.rejected_folder:
                return 403, {}
            if folder in self.folders:
                self.folders[folder].update(request)
                return 200, {}
        return "unexpected", {}


@contextmanager
def serving(fixture, role):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def process(self):
            length = int(self.headers.get("Content-Length", 0))
            request = json.loads(self.rfile.read(length)) if length else None
            action, payload = fixture.answer(role, self.command, self.path, request)
            if role == "submit" and fixture.block_at == self.command:
                fixture.barrier.set()
                fixture.release.wait(FIXTURE_LIMIT)
            if action == "drop":
                self.close_connection = True
                with suppress(OSError):
                    self.connection.shutdown(socket.SHUT_RDWR)
                return
            try:
                if action == "headers_403":
                    self.send_response(403)
                    self.send_header("Content-Length", "512")
                    self.end_headers()
                    self.wfile.write(b"{")
                    self.wfile.flush()
                    fixture.barrier.set()
                    fixture.release.wait(FIXTURE_LIMIT)
                    return
                body = json.dumps(payload).encode()
                self.send_response(404 if action == "unexpected" else action)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = process
        do_PATCH = process
        do_DELETE = process

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            fixture.release.set()
            server.shutdown()
            thread.join(timeout=FIXTURE_LIMIT)
            if thread.is_alive():
                raise RuntimeError("the isolated HTTP server did not exit")


def connection(endpoint):
    return {"endpoint": endpoint, "api_key": KEY, "expected_device_id": OWN}


def run(executable, command, data, *, approval=None):
    lines = json.dumps(data)
    if approval is not None:
        lines += "\n" + approval + "\n"
    return subprocess.run([str(executable), *map(str, command)], input=lines,
                          encoding="utf-8", capture_output=True, timeout=FIXTURE_LIMIT)


def result(process):
    return {"exit": process.returncode, "stdout": process.stdout, "stderr": process.stderr}


def public(process):
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError:
        return {}


def visible_receipt(path):
    if not path.is_file():
        return {}
    receipt = json.loads(path.read_text(encoding="utf-8"))
    facts = {key: receipt.get(key) for key in ("operation_id", "submission", "response_status")}
    progress = receipt.get("intent", {}).get("progress")
    if progress is not None:
        facts["device_removal_progress"] = progress
    return facts


class Evidence:
    def __init__(self, name):
        self.name = name
        self.failures = []

    def require(self, effect, description):
        if not effect:
            self.failures.append(description)

    def write(self, fixture, **facts):
        self.require(all(action != "unexpected" for _, _, _, action in fixture.requests),
                     "all upstream routes were expected")
        record = {"case": self.name, **facts, "ordered_requests": fixture.requests,
                  "unmet_assertions": self.failures}
        encoded = json.dumps(record, ensure_ascii=True)
        if KEY in encoded:
            self.failures.append("fixture credential appeared in the public evidence")
            encoded = json.dumps(record, ensure_ascii=True).replace(KEY, "<redacted>")
        print(encoded, flush=True)
        return not self.failures


def assert_wire(evidence, fixture, expected):
    mutations = [(method, route) for role, method, route, _ in fixture.requests
                 if role == "submit" and method != "GET"]
    evidence.require(mutations == expected, f"upstream writes must be exactly {expected}")
    evidence.require(all(method == "GET" for role, method, _, _ in fixture.requests
                         if role == "readback"), "recovery sent zero writes")


def assert_independent_read(evidence, fixture, route):
    writes = [index for index, (role, method, _, _) in enumerate(fixture.requests)
              if role == "submit" and method != "GET"]
    reads = [index for index, (role, method, path, _) in enumerate(fixture.requests)
             if role == "readback" and method == "GET" and path == route]
    evidence.require(len(reads) == 1 and (not writes or writes[-1] < reads[0]),
                     "independent readback reached the selected resource after submission")


def assert_public(evidence, summary, process, *, code, stage, failure,
                  status=None, complete=None, message_parts=()):
    evidence.require(process.returncode == code, f"exit status {code}")
    evidence.require(summary.get("failure_stage") == stage, f"failure stage {stage!r}")
    evidence.require(summary.get("failure") == failure, f"failure classification {failure!r}")
    if status is not None:
        evidence.require(summary.get("http_status") == status, f"observed HTTP status {status}")
    if complete is not None:
        evidence.require(summary.get("response_complete") is complete,
                         f"response completeness {complete}")
    message = summary.get("message", "").lower()
    for fragment in message_parts:
        evidence.require(fragment.lower() in message, f"public message contains {fragment!r}")


def submission_case(executable, scenario):
    evidence = Evidence("B-" + scenario)
    is_removal = scenario.startswith("device")
    command = "remove-device" if is_removal else "submit"
    observe = "observe-device" if is_removal else "observe"
    parts = scenario.split("-")
    reply = 200
    if parts[-1] in ("401", "403") and "headers" not in parts and "read" not in parts:
        reply = int(parts[-1])
    elif "headers" in parts:
        reply = "headers_403"
    elif "drop" in parts:
        reply = "drop"
    config_read = {
        "device-pre-read-403": "before",
        "device-post-read-403": "post_delete",
        "device-pause-read-403": "after_pause",
    }.get(scenario)
    fixture = Fixture(gui_reply=200 if is_removal else reply,
                      delete_reply=reply if is_removal else 200,
                      config_read=config_read)
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vs-output-")))
        submit_endpoint = stack.enter_context(serving(fixture, "submit"))
        readback_endpoint = stack.enter_context(serving(fixture, "readback"))
        data = connection(submit_endpoint)
        recovery_data = connection(readback_endpoint)
        if is_removal:
            data["peer_id"] = PEER
        else:
            data["bind"] = NEW_ADDRESS
        if scenario == "device-pause-read-403":
            data["disconnect_timeout_ms"] = 5000
        if reply == "headers_403":
            data["timeout_ms"] = BODY_DEADLINE_MS
        start = time.monotonic()
        submitted = run(executable, (command, root), data)
        elapsed = time.monotonic() - start
        summary = public(submitted)
        receipt = visible_receipt(root / "receipt.json")
        observed_process = run(executable, (observe, root), recovery_data)
        observed = public(observed_process)
        evidence.require(observed_process.returncode == 0, "second process reopened the receipt")
        evidence.require(observed.get("operation_id") == summary.get("operation_id") is not None,
                         "second process retained the operation identity")
        requested = [("DELETE", DEVICE)] if is_removal else [("PATCH", GUI)]
        if config_read == "before":
            requested = []
            assert_public(evidence, summary, submitted, code=1, stage="pre_submit_read",
                          failure="authentication", message_parts=("read",))
            evidence.require(summary.get("http_status") is None
                             and summary.get("response_complete") is None,
                             "the pre-submit denial is not recorded as a write response")
            msg = summary.get("message", "").lower()
            evidence.require("not submitted" in msg or "no removal" in msg or "was not sent" in msg,
                             "the failed read did not dispatch a removal")
        elif config_read == "after_pause":
            requested = [("PATCH", DEVICE)]
            assert_public(evidence, summary, submitted, code=2, stage="pause_read",
                          failure="mutation_outcome_unknown", message_parts=("paus", "read"))
            evidence.require(summary.get("device_removal_progress", {}).get("pause_request")
                             == {"state": "acknowledged", "status": 200},
                             "acknowledged pause remained visible")
        elif config_read == "post_delete":
            assert_public(evidence, summary, submitted, code=2, stage="post_submit_read",
                          failure="mutation_outcome_unknown", status=200, complete=True,
                          message_parts=("acknowledged", "cannot read the device registration",
                                         "check read permissions", "after access is restored",
                                         "use observe-device"))
            evidence.require(summary.get("read_http_status") == 403, "readback HTTP 403")
            message = summary.get("message", "").lower()
            evidence.require(
                0 <= message.find("check read permissions")
                < message.find("after access is restored")
                < message.find("use observe-device"),
                "public guidance restores permissions before asking for a read-only check",
            )
        elif reply in (401, 403):
            fragment = "authenticat" if reply == 401 else "refus"
            assert_public(evidence, summary, submitted, code=1, stage="submit",
                          failure="authentication", status=reply, complete=True,
                          message_parts=(fragment,))
            evidence.require(receipt.get("response_status") == reply,
                             "durable receipt retains refusal response status")
        elif reply == "headers_403":
            assert_public(evidence, summary, submitted, code=2, stage="submit",
                          failure="mutation_outcome_unknown", status=403, complete=False)
            message = summary.get("message", "").lower()
            evidence.require("headers" in message and
                             ("did not finish" in message or "incomplete" in message),
                             "the public message reports received headers and incomplete reply")
            evidence.require(fixture.barrier.is_set(), "fixture actually flushed partial response")
            evidence.require(elapsed >= BODY_DEADLINE_MS / 1000,
                             "the held response expired at the request deadline")
            evidence.require(receipt.get("response_status") == 403,
                             "receipt retains the observed header")
        elif reply == "drop":
            assert_public(evidence, summary, submitted, code=2, stage="submit",
                          failure="mutation_outcome_unknown", complete=False,
                          message_parts=("observe",))
            evidence.require(receipt.get("response_status") is None,
                             "no response status was fabricated")
        else:
            evidence.require(submitted.returncode == 0, "acknowledged positive control")
            evidence.require(summary.get("submission") == "acknowledged",
                             "positive control is acknowledged")
        assert_wire(evidence, fixture, requested)
        assert_independent_read(evidence, fixture, CONFIG if is_removal else GUI)
        if is_removal:
            evidence.require(observed.get("configuration_absent") is (not fixture.registered),
                             "readback matches actual fixture registration state")
        else:
            evidence.require(observed.get("requested_fields_match") is (fixture.address == NEW_ADDRESS),
                             "readback matches actual fixture listener state")
        evidence.require(summary.get("submission") == receipt.get("submission", {}).get("state"),
                         "the published summary preserves the durable submission state")
        return evidence.write(fixture, submit=result(submitted), reopened=result(observed_process),
                              receipt=receipt, elapsed_ms=round(elapsed * 1000))


def preview_case(executable, scenario):
    evidence = Evidence("C-" + scenario)
    refusal = 401 if scenario == "refused-401" else 403
    if scenario.startswith("refused"):
        reply = refusal
    elif scenario == "drop":
        reply = "drop"
    else:
        reply = 200
    fixture = Fixture(gui_reply=reply,
                      prior_address=NEW_ADDRESS if scenario == "refused-403-equal" else OLD_ADDRESS,
                      failed_readback=scenario == "readback-failed",
                      rejected_folder="folder-b" if scenario == "partial-folder" else None)
    with serving(fixture, "submit") as submit_endpoint, serving(fixture, "readback") as readback:
        data = {"connection": connection(submit_endpoint), "readback": connection(readback)}
        if scenario == "partial-folder":
            data["folders"] = [
                {"id": name, "label": "synthetic-new-label"} for name in fixture.folders
            ]
        else:
            data["listener"] = {"bind": NEW_ADDRESS}
        process = run(executable, (), data,
                      approval="decline" if scenario == "preview-only" else "apply")
        output = process.stdout.lower()
        expected = [("PATCH", GUI)]
        if scenario.startswith("refused"):
            evidence.require(process.returncode == 1, "an explicit refusal exits one")
            evidence.require(f"http {refusal}" in output, "the original HTTP rejection is visible")
            evidence.require("refus" in output if refusal == 403 else "authenticat" in output,
                             "permission refusal and authentication rejection are distinguished")
            evidence.require("acknowledgement is still unknown" not in output,
                             "a complete refusal is not called an unknown acknowledgement")
            field_lines = [line for line in output.splitlines()
                           if line.startswith("management listener address.")]
            field_line = field_lines[-1] if field_lines else ""
            if scenario == "refused-403-equal":
                evidence.require("matches" in field_line or "reports the requested value" in field_line,
                                 "independent current value matches")
            else:
                evidence.require("differs" in field_line, "independent current value differs")
        elif scenario == "preview-only":
            expected = []
            evidence.require(process.returncode == 0, "user declined the preview")
            evidence.require("without sending any changes" in output, "pre-approval preview remains read only")
        elif scenario == "drop":
            evidence.require("unknown" in output, "the missing acknowledgement remains visible")
            evidence.require("reports the requested value" in output or "currently matches" in output,
                             "independent current value is separately confirmed")
        elif scenario == "readback-failed":
            evidence.require(process.returncode == 1, "failed verification exits one")
            evidence.require("acknowledged" in output, "the original acknowledgement remains visible")
            evidence.require("could not be checked" in output and "unconfirmed" in output,
                             "failed verification leaves the current value unconfirmed")
        elif scenario == "partial-folder":
            expected = [("PATCH", FOLDERS + "folder-a"), ("PATCH", FOLDERS + "folder-b")]
            evidence.require(process.returncode == 1, "partial commit exits one")
            stages = output.split("result for resource ")
            if len(stages) == 4:
                _, first, second, last = stages
            else:
                first = second = last = ""
            evidence.require(first.startswith("1.") and "acknowledged" in first
                             and ("reports the requested value" in first or "currently matches" in first),
                             "the first step independently reports its acknowledged, matching result")
            evidence.require(second.startswith("2.") and "http 403" in second and "refus" in second,
                             "the second step records the original refusal")
            evidence.require(last.startswith("3.") and "no change was sent" in last,
                             "the final step remains unexecuted")
            labels = [profile["label"] for profile in fixture.folders.values()]
            evidence.require(labels == ["synthetic-new-label", "synthetic-original-label",
                                        "synthetic-original-label"],
                             "actual folder data confirms no implicit rollback or retry")
        else:
            evidence.require(process.returncode == 0, "acknowledged matching fields exit zero")
            evidence.require("acknowledged" in output and
                             ("reports the requested value" in output or "currently matches" in output),
                             "original acknowledgement and current values are both reported")
        assert_wire(evidence, fixture, expected)
        if scenario not in ("preview-only", "partial-folder"):
            assert_independent_read(evidence, fixture, GUI)
        return evidence.write(fixture, command=result(process))


def interrupted_case(executable, after_write):
    evidence = Evidence("A2-interrupted-after" if after_write else "A2-interrupted-before")
    fixture = Fixture(gui_reply="drop" if after_write else 200)
    fixture.block_at = "PATCH" if after_write else None
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vs-output-exit-")))
        submit_endpoint = stack.enter_context(serving(fixture, "submit"))
        readback = stack.enter_context(serving(fixture, "readback"))
        if not after_write:
            upstream = fixture.answer

            def signal_before_write(role, method, route, payload):
                reply = upstream(role, method, route, payload)
                if role == "submit" and method == "GET" and route == GUI:
                    fixture.barrier.set()
                    fixture.release.wait(FIXTURE_LIMIT)
                return reply

            fixture.answer = signal_before_write
        with subprocess.Popen([str(executable), "submit", str(root)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8") as proc:
            try:
                proc.stdin.write(json.dumps({**connection(submit_endpoint), "bind": NEW_ADDRESS}))
                proc.stdin.close()
                if not fixture.barrier.wait(FIXTURE_LIMIT):
                    raise RuntimeError("the selected process did not reach the fixture barrier")
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=FIXTURE_LIMIT)
                fixture.release.set()
            exit_code = proc.returncode
        receipt = visible_receipt(root / "receipt.json")
        observed_process = run(executable, ("observe", root), connection(readback))
        observation = public(observed_process)
        expected = "possibly_submitted" if after_write else "prepared"
        evidence.require(receipt.get("submission", {}).get("state") == expected,
                         f"the durable process-exit checkpoint is {expected}")
        evidence.require(observed_process.returncode == 0,
                         "a second process independently reopened the prior checkpoint")
        evidence.require(observation.get("submission") == expected,
                         "read-only reopening preserves the original uncertainty")
        evidence.require(observation.get("operation_id") == receipt.get("operation_id") is not None,
                         "recovery preserves the interrupted operation identity")
        evidence.require(observation.get("requested_fields_match") is after_write,
                         "actual state independently distinguishes the interruption stages")
        assert_wire(evidence, fixture, [("PATCH", GUI)] if after_write else [])
        assert_independent_read(evidence, fixture, GUI)
        return evidence.write(fixture, killed_process_exit=exit_code,
                              reopened=result(observed_process), receipt=receipt)


def initial_storage_failure(executable):
    evidence = Evidence("A2-initial-save-no-clobber")
    fixture = Fixture()
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vs-output-existing-")))
        first_endpoint = stack.enter_context(serving(fixture, "previous_operation"))
        endpoint = stack.enter_context(serving(fixture, "submit"))
        readback_endpoint = stack.enter_context(serving(fixture, "readback"))
        first = run(executable, ("submit", root),
                    {**connection(first_endpoint), "bind": OLD_ADDRESS})
        saved = root / "receipt.json"
        evidence.require(first.returncode == 0 and saved.is_file(),
                         "a real earlier operation created a valid private receipt")
        digest = sha256(saved.read_bytes()).hexdigest()
        process = run(executable, ("submit", root),
                      {**connection(endpoint), "bind": NEW_ADDRESS})
        observed = run(executable, ("observe", root), connection(readback_endpoint))
        evidence.require(process.returncode == 1, "initial save refusal exits one")
        evidence.require(public(process).get("failure") == "receipt_storage",
                         "initial save refusal is attributed to receipt storage")
        evidence.require(sha256(saved.read_bytes()).hexdigest() == digest,
                         "the preexisting operation record is byte-identical")
        evidence.require(observed.returncode == 0
                         and public(observed).get("operation_id") == public(first).get("operation_id"),
                         "a second process reopened the earlier operation rather than the refused one")
        assert_wire(evidence, fixture, [])
        assert_independent_read(evidence, fixture, GUI)
        return evidence.write(fixture, previous=result(first), submit=result(process),
                              reopened=result(observed), preserved_sha256=digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listener", type=Path, required=True)
    parser.add_argument("--preview", type=Path, required=True)
    parser.add_argument("--only", choices=("A2", "B", "C"))
    args = parser.parse_args()
    # Keep all synthetic requests on loopback independently of inherited proxy configuration.
    for key in tuple(os.environ):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            os.environ.pop(key)
    results = []
    if args.only in (None, "A2"):
        results.append(initial_storage_failure(args.listener))
        results.extend(interrupted_case(args.listener, after) for after in (False, True))
    if args.only in (None, "B"):
        for scenario in (
            "gui-401", "gui-403", "gui-headers-403", "gui-drop", "gui-success",
            "device-401", "device-403", "device-headers-403", "device-drop",
            "device-success", "device-pre-read-403", "device-post-read-403",
            "device-pause-read-403",
        ):
            results.append(submission_case(args.listener, scenario))
    if args.only in (None, "C"):
        for scenario in (
            "refused-403-equal", "refused-403-different", "refused-401", "preview-only",
            "success", "drop", "readback-failed", "partial-folder",
        ):
            results.append(preview_case(args.preview, scenario))
    print(json.dumps({"summary": {"passed": sum(results), "total": len(results)}}), flush=True)
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
