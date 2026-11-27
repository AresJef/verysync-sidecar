"""Known-answer loopback controls for transport boundaries and file progress.

These controls exercise fixture-layer observers. Native upgrade and file cases
stay in the unchanged natural group.
"""
from contextlib import contextmanager
from hashlib import sha256
from http.client import HTTPConnection, IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import threading
import time

from collect import event, write_json


@contextmanager
def metadata_server(close_before_body):
    transmitted = []
    body = b'{"version":"2.33.2","fixture_only":true}'

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            transmitted.append({"phase": "request_received", "clock_ns": time.monotonic_ns()})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            fragment = body[:2] if close_before_body else body
            self.wfile.write(fragment)
            self.wfile.flush()
            transmitted.append({"phase": "bytes_sent", "bytes": len(fragment),
                                "clock_ns": time.monotonic_ns()})
            if close_before_body:
                self.connection.shutdown(socket.SHUT_WR)
            self.close_connection = True

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield server.server_address[1], body, transmitted
        finally:
            server.shutdown()
            thread.join()
            if thread.is_alive():
                raise RuntimeError("loopback metadata actor did not exit")


def metadata(close_before_body):
    started = time.monotonic_ns()
    with metadata_server(close_before_body) as (port, expected, witness):
        client = HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            client.request("GET", "/synthetic-upgrade-metadata")
            reply = client.getresponse()
            try:
                actual = reply.read()
                message = "Metadata response completed."
                err = None
            except IncompleteRead as failure:
                actual = failure.partial
                message = "Metadata response did not complete."
                err = type(failure).__name__
        finally:
            client.close()
    ending = time.monotonic_ns()
    partial = bool(err)
    return {"scope": "loopback HTTP fixture; SDK, provider and CLI were not used",
            "assertion_passed": (partial == close_before_body and reply.status == 200
                                 and len(actual) == (2 if partial else len(expected))),
            "caller": {"message": message, "underlying_type": err},
            "ci": {"status_header": reply.status, "read_bytes": len(actual),
                   "declared_bytes": len(expected), "observed_end_ns": ending,
                   "began_ns": started, "request_deadline_ms": 2000,
                   "server": witness, "completed_sha256": sha256(actual).hexdigest() if not partial else None},
            "truth": {"stage": "headers_then_eof" if partial else "full_response",
                      "effect": "no_write", "next": "read_only_retry" if partial else "continue"}}


def progress(root, later_progress):
    sample = b"section28 deterministic receiver bytes\n" * 500
    path = root / "received-synthetic.bin"
    first = threading.Event()
    released = threading.Event()
    done = threading.Event()
    writes = []
    issues = []

    def receiver():
        try:
            with path.open("xb") as dst:
                fragment = sample[:128]
                dst.write(fragment)
                dst.flush()
                writes.append({"bytes": len(fragment), "clock_ns": time.monotonic_ns()})
                first.set()
                if not released.wait(3):
                    raise TimeoutError("controller did not release the transfer actor")
                if later_progress:
                    dst.write(sample[128:])
                    dst.flush()
                    writes.append({"bytes": len(sample), "clock_ns": time.monotonic_ns()})
        except (OSError, TimeoutError) as error:
            issues.append(type(error).__name__)
        finally:
            done.set()

    started = time.monotonic_ns()
    actor = threading.Thread(target=receiver)
    actor.start()
    try:
        first_ready = first.wait(2)
        deadline_finished = not done.wait(0.08)
        deadline_at = time.monotonic_ns()
        at_deadline = path.stat().st_size
        if later_progress:
            released.set()
        done.wait(0.12)
        observed_until = time.monotonic_ns()
        at_window = path.stat().st_size
        observed = sha256(path.read_bytes()).hexdigest()
    finally:
        released.set()
        actor.join(timeout=3)
    expected_sha = sha256(sample).hexdigest()
    reached_end = observed == expected_sha
    rendered = "The receiver did not complete within the original observation window."
    return {"scope": "synthetic local file/observer fixture; native transfer and its deadline are separate",
            "assertion_passed": (first_ready and deadline_finished and not issues
                                 and at_deadline == 128 and not actor.is_alive()
                                 and reached_end == later_progress
                                 and at_window == (len(sample) if later_progress else at_deadline)),
            "caller": {"message": rendered, "timeout_ms": 80},
            "ci": {"start_ns": started, "deadline_witness_ns": deadline_at,
                   "last_observed_ns": observed_until, "at_deadline_bytes": at_deadline,
                   "at_window_bytes": at_window, "sender_bytes": len(sample),
                   "sender_sha256": expected_sha, "receiver_sha256": observed,
                   "receiver_write_witness": writes, "actor_exited": not actor.is_alive()},
            "truth": {"stage": "later_completed" if later_progress else "no_new_progress_in_window",
                      "effect": "complete_file" if later_progress else "partial_file",
                      "next": "continue" if later_progress else "stop_and_preserve"}}


def run(evidence, root):
    private = root / "I04"
    private.mkdir()
    results = []
    for case, fixture in (
        ("I04-METADATA-COMPLETE", lambda _: metadata(False)),
        ("I04-METADATA-CLOSED", lambda _: metadata(True)),
        ("I04-PROGRESS-LATE", lambda folder: progress(folder, True)),
        ("I04-PROGRESS-STILL", lambda folder: progress(folder, False)),
    ):
        event(evidence, "supplemental_control_dispatch", case=case)
        folder = private / case
        folder.mkdir()
        result = fixture(folder)
        # These are separate payloads so a blind reader can receive only the requested view.
        write_json(evidence / "I04-visible" / f"{case}.json",
                   {key: result[key] for key in ("scope", "caller", "ci")})
        write_json(evidence / "I04-truth" / f"{case}.json",
                   {key: result[key] for key in ("assertion_passed", "truth")})
        event(evidence, "supplemental_control_result", case=case, passed=result["assertion_passed"])
        results.append(result["assertion_passed"])
    return all(results)
