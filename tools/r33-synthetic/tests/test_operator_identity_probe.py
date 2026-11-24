"""Repeat the no-secret challenge through separate disposable OS identities."""

import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile

from r33_isolation import read_proof
from test_terminal import BUNDLE, TMP, Terminal


def probe(executor, program, challenge):
    return subprocess.run(
        ["/usr/bin/sudo","-n","-u",executor,"/usr/bin/python3","-E","-s","-B",str(program),
         "executor","--challenge",str(challenge)],
        capture_output=True,timeout=10,
    )


def main():
    os.umask(0o077)
    account, other = ("nobody","_www" if sys.platform=="darwin" else "daemon")
    executor = pwd.getpwnam(account).pw_uid
    domain = "/private/tmp" if sys.platform=="darwin" else "/tmp"
    with tempfile.TemporaryDirectory(prefix="r33-probe-uid-",dir=domain) as root, \
            tempfile.TemporaryDirectory(prefix="r33-probe-read-",dir=domain) as shared:
        private, public = Path(root).resolve(),Path(shared).resolve()
        for name in ("r33_isolation.py","r33_protocol.py"):
            code=public/name
            shutil.copyfile(BUNDLE/name,code)
            code.chmod(0o444)
        public.chmod(0o711)
        proof=private/"verified.json"
        watcher=Terminal(["operator","--executor-uid",str(executor),"--record",str(proof)],"r33_isolation.py")
        try:
            marker=b"R33_ISOLATION "
            watcher.prompt(marker)
            offset=watcher.buffer.index(marker)+len(marker)
            watcher.prompt(b".json")
            path=Path(watcher.buffer[offset:].splitlines()[0].decode().strip())
            assert path.exists()
            denied=probe(other,public/"r33_isolation.py",path)
            assert denied.returncode==2 and not proof.exists(),denied.stdout
            allowed=probe(account,public/"r33_isolation.py",path)
            assert allowed.returncode==0,(allowed.returncode,allowed.stdout)
            assert watcher.wait(5)==0
            result=read_proof(proof,executor)
            assert result["private_file_unreadable"] and result["private_socket_denied"]
            assert not path.exists()
        finally:
            watcher.close()
    print(json.dumps({"verified_real_system_identity":result["executor_uid"],
                      "verified_owner":result["operator_uid"], "unrelated_account_refused":True,
                      "private_file_unreadable":True,"private_management_socket_denied":True,
                      "probe_state_cleaned":True}))


if __name__=="__main__":
    main()
