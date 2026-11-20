"""Small, immutable encrypted messages on a dedicated project test branch."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, HTTPRedirectHandler, build_opener


REPO = "AresJef/verysync-sidecar"
BRANCH = "test/tracker-retry-rendezvous-20261120"
ROOT = "https://api.github.com/repos/" + REPO + "/contents/field-signal/"


class RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        del args, kwargs
        return None


class Signal:
    def __init__(self, token, key, source):
        if not token or not re.fullmatch("[0-9a-f]{64}", key):
            raise ValueError("isolated coordinator authorization missing")
        self.token = token
        self.key = key
        self.source = source
        self.opener = build_opener(RefuseRedirect())
        self.seal_program = Path(__file__).with_name("seal.mjs")

    def crypto(self, mode, name, value):
        request = {"mode": mode, "key": self.key, "label": f"{BRANCH}:{self.source}:{name}",
                   "value": value}
        cmd = ["node", str(self.seal_program)]
        result = subprocess.run(cmd, input=json.dumps(request), capture_output=True, text=True, timeout=6)
        if result.returncode != 0:
            raise ValueError("isolated coordinator seal verification failed")
        return json.loads(result.stdout) if mode == "open" else result.stdout

    def request(self, method, name, payload=None):
        if not re.fullmatch("(mac|linux)-[a-z0-9-]{1,28}", name):
            raise ValueError("invalid private control record name")
        url = ROOT + name + ".sealed"
        if method == "GET":
            url += "?" + urlencode({"ref": BRANCH})
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
                   "User-Agent": "verysync-sidecar-isolated-test", "Content-Type": "application/json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        query = Request(url, data=body, headers=headers, method=method)
        with self.opener.open(query, timeout=12) as response:
            return json.loads(response.read(200000))

    def read(self, name):
        try:
            result = self.request("GET", name)
        except HTTPError as error:
            if error.code == 404:
                return None
            raise
        blob = base64.b64decode(result["content"]).decode("ascii")
        return self.crypto("open", name, blob)

    def put(self, name, value):
        blob = self.crypto("seal", name, value)
        body = {"message": "Record a sealed isolated acceptance signal", "branch": BRANCH,
                "content": base64.b64encode(blob.encode("ascii")).decode()}
        for attempt in range(4):
            try:
                self.request("PUT", name, body)
                return
            except HTTPError as error:
                if error.code not in (409, 422, 429, 502, 503, 504):
                    raise
            except (URLError, TimeoutError):
                pass
            try:
                if self.read(name) == value:
                    return
            except HTTPError as error:
                if error.code not in (429, 502, 503, 504):
                    raise
            except (URLError, TimeoutError):
                pass
            time.sleep(0.75 * (attempt + 1))
        raise RuntimeError("could not record one sealed coordination message")

    def wait(self, name, seconds):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            try:
                if result := self.read(name):
                    return result
            except HTTPError as error:
                if error.code not in (429, 502, 503, 504):
                    raise
            except (URLError, TimeoutError):
                pass
            time.sleep(1.5)
        raise TimeoutError("required sealed coordination message did not arrive")


def local_project_token():
    checkout = "/private/tmp/vs-followup-ci-20261120"
    request = "protocol=https\nhost=github.com\npath=AresJef/verysync-sidecar.git\n\n"
    process = subprocess.run(["git","credential","fill"],cwd=checkout,env=dict(os.environ,GIT_TERMINAL_PROMPT="0"),
                             input=request, capture_output=True, text=True, timeout=10, check=True)
    return dict(item.split("=",1) for item in process.stdout.splitlines() if "=" in item)["password"]
