"""Verify the actual cross-user Unix boundary in a disposable standard VM."""

import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import tempfile

from test_account_terminal import make_fixture, provider
from test_terminal import TMP, Terminal


def viewer(path, account, endpoint, run, key, session, backend):
    result = subprocess.run(
        ["/usr/bin/sudo", "-n", "-u", account, "/usr/bin/python3", "-I", str(path),
         str(endpoint), run, str(key), str(session), str(backend)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    return json.loads(result.stdout)


def main(output):
    os.umask(0o077)
    intended = "nobody"
    unrelated = "_www" if sys.platform == "darwin" else "daemon"
    tested_uid = pwd.getpwnam(intended).pw_uid
    unrelated_uid = pwd.getpwnam(unrelated).pw_uid
    assert len({os.getuid(),tested_uid,unrelated_uid,0}) == 4
    with tempfile.TemporaryDirectory(prefix="r33-uid-a-", dir=TMP) as private_dir, \
            tempfile.TemporaryDirectory(prefix="r33-uid-b-", dir=TMP) as public_dir:
        private, public = Path(private_dir).resolve(), Path(public_dir).resolve()
        directory, storage, backend, profile, username, password = make_fixture(private)
        key = private/"fixture-key"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       check=True, timeout=5)
        agent_code = public/"view.py"
        shutil.copyfile(Path(__file__).with_name("unprivileged_view.py"), agent_code)
        agent_code.chmod(0o444)
        public.chmod(0o711)
        journal = private/"foreground.jsonl"
        with provider(directory):
            user = Terminal(["start","--synthetic","--profile",str(profile),"--evidence",str(journal),
                             "--executor-uid",str(tested_uid),"--minutes","3"])
            try:
                user.feed(b"START\n")
                user.prompt(b"VerySync account (hidden) ")
                user.feed(username+b"\n")
                user.prompt(b"VerySync password (hidden) ")
                user.feed(password+b"\n")
                ready = user.response(b"R33_READY ")
                run, endpoint = ready["run"], Path(ready["socket"])
                session = storage/run/"session"
                assert len(session.read_text()) == 32 and key.stat().st_size>0
                first = viewer(agent_code, intended, endpoint, run, key, session, backend)
                second = viewer(agent_code, unrelated, endpoint, run, key, session, backend)
                assert first == {
                    "actual_uid":tested_uid,"allowed":{"ok":True,"signed_in":True},
                    "wrong_scope_denied":True,"wrong_run_denied":True,"operator_stop_denied":True,
                    "synthetic_key_read_denied":True,"synthetic_cookie_read_denied":True,
                    "private_service_connect_denied":True,
                }, first
                assert second == first | {
                    "actual_uid":unrelated_uid,"allowed":{"ok":False,"code":"denied"},
                }, second
                user.feed(b"\x03")
                terminal = user.response(b"R33_STOPPED ", 8)
                assert terminal["local"] == "revoked"
                assert terminal["pro"]["state"] == "synthetic-session-closed"
                assert user.wait(5) == 0 and not endpoint.exists() and not session.exists()
                assert username not in user.observed and password not in user.observed
            finally:
                user.close()
        assert not backend.exists()
    assert not private.exists() and not public.exists()
    receipt = {"os":platform.platform(),"machine":platform.machine(),"operator_uid":os.getuid(),
               "execution":first,"unrelated":second,"terminal":terminal,"all_fixture_paths_removed":True}
    output.write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
