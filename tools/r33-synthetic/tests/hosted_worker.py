"""A temporary, no-network, no-credential job used to observe cancellation."""

import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    requested = None

    def cancel(signum, _frame):
        nonlocal requested
        requested = signal.Signals(signum).name

    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="r33-hosted-") as raw:
        directory = Path(raw)
        marker = directory/"sample"
        marker.write_text("synthetic fixture only\n")
        child = subprocess.Popen(["/usr/bin/sleep", "240"], start_new_session=True)
        print(json.dumps({"r33":"owned-worker-started", "pid":child.pid, "sample_present":marker.is_file()}),
              flush=True)
        try:
            while requested is None and time.monotonic()-start < 120:
                time.sleep(.1)
        finally:
            if child.poll() is None:
                child.terminate()
            status = child.wait(2)
    print(json.dumps({"r33":"owned-worker-stopped", "signal":requested or "fixture-deadline",
                      "exit":status,"sample_directory_removed":not directory.exists(),
                      "elapsed":round(time.monotonic()-start, 4)}), flush=True)


if __name__ == "__main__":
    main()
