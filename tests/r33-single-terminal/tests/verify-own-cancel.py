"""Ask GitHub to cancel only this synthetic runner and prove the owned exit."""

import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import subprocess
import tempfile
import time


REPOSITORY = "AresJef/verysync-sidecar"
BRANCH = "refs/heads/ci/r33-synthetic-20261124"


def main():
    run = os.environ["GITHUB_RUN_ID"]
    if (os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != BRANCH or not re.fullmatch(r"[0-9]{8,20}",run)
            or os.environ.get("GITHUB_JOB") != "self-cancel"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("This test only cancels its own synthetic hosted job.")
    token = os.environ.pop("R33_OWN_RUN_CANCEL_TOKEN")
    stopped = []

    def acknowledge_stop(kind, _frame):
        stopped.append(signal.Signals(kind).name)

    signal.signal(signal.SIGINT, acknowledge_stop)
    signal.signal(signal.SIGTERM, acknowledge_stop)
    with tempfile.TemporaryDirectory(prefix="r33-self-cancel-") as raw:
        owned = Path(raw)
        (owned/"sample").write_bytes(b"synthetic run-specific worker")
        worker = subprocess.Popen(["/bin/sleep","180"],cwd=owned,
                                  stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                  start_new_session=True,env={"PATH":"/usr/bin:/bin"})
        try:
            assert worker.poll() is None
            conn = http.client.HTTPSConnection("api.github.com",timeout=12,context=ssl.create_default_context())
            try:
                conn.request("POST",f"/repos/{REPOSITORY}/actions/runs/{run}/cancel",
                             headers={"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json",
                                      "User-Agent":"verysync-sidecar-synthetic-job",
                                      "X-GitHub-Api-Version":"2022-11-28"})
                with conn.getresponse() as reply:
                    status = reply.status
            finally:
                conn.close()
                token = None
            assert status==202,status
            print("R33_GITHUB_CANCEL_REQUEST "+json.dumps({"run":run,"http_status":status}),flush=True)
            limit = time.monotonic()+75
            while not stopped and time.monotonic()<limit:
                time.sleep(.1)
            assert stopped, "The hosted runner did not deliver the cancellation signal."
        finally:
            if worker.poll() is None:
                worker.terminate()
            worker.wait(timeout=4)
    print("R33_GITHUB_CANCEL_EXIT "+json.dumps({"run":run,"signal":stopped[0],
              "owned_child_exited":worker.poll() is not None,"owned_directory_removed":not owned.exists()}),flush=True)


if __name__ == "__main__":
    main()

