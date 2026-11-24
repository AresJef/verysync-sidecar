"""A private persistent account substitute for the revocation acceptance tests."""

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import sys

from r33_protocol import FRAME_MAX, decode_frame, encode_frame


async def run(root):
    directory = root.resolve()
    expected = json.loads((directory/"expect.json").read_text())
    session = directory/"login.json"
    stop = asyncio.Event()

    def handle(obj):
        kind = obj.get("kind")
        active = json.loads(session.read_text()) if session.is_file() else None
        if kind == "login" and set(obj) == {"kind","username","password"} and active is None:
            if any(type(obj[name]) is not str for name in ("username","password")):
                return {"ok":False,"code":"rejected"}
            for name in ("username","password"):
                actual = hashlib.sha256(obj[name].encode()).hexdigest()
                if not hmac.compare_digest(actual,expected[name]):
                    return {"ok":False,"code":"rejected"}
            token = secrets.token_hex(16)
            with session.open("x") as stream:
                stream.write(json.dumps(token))
            return {"ok":True,"session":token}
        if kind in ("inspect","logout") and set(obj)=={"kind","session"}:
            if active is None or type(obj["session"]) is not str or not hmac.compare_digest(active,obj["session"]):
                return {"ok":False,"code":"signed-out"}
            if kind=="logout":
                session.unlink()
            return {"ok":True}
        return {"ok":False,"code":"denied"}

    async def connection(reader,writer):
        try:
            line=await asyncio.wait_for(reader.readline(),2)
            writer.write(encode_frame(handle(decode_frame(line))))
            await writer.drain()
        except (OSError,ValueError,asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    path=directory/"account.sock"
    server=await asyncio.start_unix_server(connection,str(path),limit=FRAME_MAX)
    for condition in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
        asyncio.get_running_loop().add_signal_handler(condition,stop.set)
    try:
        print("ACCOUNT_FIXTURE_READY",flush=True)
        await stop.wait()
    finally:
        server.close()
        await server.wait_closed()
        path.unlink(missing_ok=True)


if __name__=="__main__":
    os.umask(0o077)
    asyncio.run(run(Path(sys.argv[1])))
