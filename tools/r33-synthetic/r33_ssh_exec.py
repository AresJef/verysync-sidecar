"""Leave the private SSH transport available for foreground Ctrl+C cleanup."""
import os
import signal
import sys

if sys.argv[1] != "/usr/bin/ssh":
    raise SystemExit(2)
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
signal.signal(signal.SIGINT, signal.SIG_IGN)
os.execv("/usr/bin/ssh", sys.argv[1:])
