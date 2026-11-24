"""Replay both password providers in one PTY using the shipped input order."""

import json
import os
from pathlib import Path
import secrets
import tempfile
import time
from unittest.mock import patch

# This fixture supplies an isolated sshd and installs the runtime import paths.
from test_root_password import disposable_sshd, local_operator, Terminal, connect, request
from r33_cases import TWO_CORE_SCOPES
from r33_single import linux_destination, update_profile
from test_account_terminal import make_fixture, provider


def exercise(base, destination, ssh_password):
    with patch("builtins.input", side_effect=[destination["host"], str(destination["port"]), "root"]) as fields:
        linux = linux_destination()
    assert fields.call_count == 3 and linux["trust_source"] == "first-use"
    folder, storage, _, profile, account, password = make_fixture(base)
    data = json.loads(profile.read_text())
    pro = data["pro"]
    pro["allow"] = ["observe", "refresh-paid", *TWO_CORE_SCOPES["pro-cases"]]
    pro["connection"]["two_core_scope"] = "pro-cases"
    profile.write_text(json.dumps(data))
    update_profile(profile, linux)
    data = json.loads(profile.read_text())
    assert list(data) == ["linux", "pro"]
    del data["pro"]["connection"]["two_core_scope"]  # The synthetic signer uses a Unix endpoint.
    profile.write_text(json.dumps(data))
    journal = base/"terminal.jsonl"
    with provider(folder):
        terminal = Terminal(["start", "--synthetic", "--executor-uid", str(os.getuid()),
                             "--profile", str(profile), "--evidence", str(journal),
                             "--expires-at", str(int(time.time()) + 145)])
        try:
            terminal.prompt(b"Type START to grant these operations.", timeout=12)
            terminal.feed(b"START\n")
            terminal.prompt(b"'s password:", timeout=12)
            terminal.feed(ssh_password + b"\n")
            terminal.prompt(b"VerySync account (hidden) ", timeout=12)
            time.sleep(16)  # Observe a real renewal while waiting on the second sign-in.
            terminal.feed(account + b"\n")
            terminal.prompt(b"VerySync password (hidden) ", timeout=8)
            terminal.feed(password + b"\n")
            ready = terminal.response(b"R33_READY ", 12)
            run, socket_path = ready["run"], Path(ready["socket"])
            token = (storage/run/"session").read_bytes()
            with connect(socket_path) as probe:
                peer = request(probe, run, "linux", "observe")
                pro_status = request(probe, run, "pro", "observe")
                assert peer["standby"] and peer["native_test_listeners"] == 0
                assert peer["renewals"] >= 1 and pro_status["ok"] and pro_status["account"] == "logged-in"
            prompts = [b"'s password:", b"VerySync account (hidden) ", b"VerySync password (hidden) "]
            assert all(terminal.observed.count(prompt) == 1 for prompt in prompts)
            assert [terminal.observed.index(prompt) for prompt in prompts] == sorted(
                terminal.observed.index(prompt) for prompt in prompts)
            markers = (ssh_password, account, password, token)
            assert all(marker not in terminal.observed and marker not in journal.read_bytes() for marker in markers)
            terminal.feed(b"\x03")
            stopped = terminal.response(b"R33_STOPPED ", 15)
            assert stopped["local"] == "revoked"
            assert stopped["linux"]["owned_worker_directory_removed"]
            assert stopped["pro"]["state"] == "synthetic-session-closed"
            assert terminal.wait(8) == 0 and not socket_path.exists()
            assert not (storage/run/"session").exists()
            return {"visible_linux_values":fields.call_count, "hidden_prompts":3,
                    "one_start":True,"linux_before_verysync":True, "ssh_renewals":peer["renewals"],
                    "ctrl_c_closed_both":True,"secrets_absent_from_transcripts":True}
        finally:
            terminal.close()


def main():
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-six-tty-", dir="/tmp") as work:
        root = Path(work)
        ssh_password = ("synthetic-root-"+secrets.token_hex(24)).encode()
        with disposable_sshd(root, ssh_password) as (destination, log):
            root.chmod(0o711)
            client = root/"client"
            with local_operator(client):
                report = exercise(client, destination, ssh_password)
            assert log.read_bytes().count(b"Accepted password for root") == 1
            print("R33_SIX_TERMINAL " + json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
