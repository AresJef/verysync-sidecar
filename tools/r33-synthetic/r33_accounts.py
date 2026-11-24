"""Private account adapters used by the foreground R33 handoff."""

import asyncio
import json
import os
from pathlib import Path
import stat
import sys
import termios

from r33_protocol import FRAME_MAX, RUN, OperatorCancelled, ProtocolError, decode_frame, encode_frame


def private_directory(path):
    info = path.lstat()
    if (not path.is_absolute() or path.resolve() != path or info.st_uid != os.getuid()
            or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077):
        raise ValueError("Choose an exclusive operator directory outside the project.")
    return path


async def hidden_line(label, stopped):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Enter the account in a private operator terminal.")
    # Read the same private terminal that receives the prompt. On Darwin the
    # special /dev/tty descriptor itself does not support this event watcher.
    descriptor = sys.stdin.fileno()
    output = sys.stderr.fileno()
    if os.ttyname(descriptor) != os.ttyname(output):
        raise ValueError("Use one private foreground terminal.")
    if stopped.is_set():
        raise OperatorCancelled
    loop = asyncio.get_running_loop()
    previous = termios.tcgetattr(descriptor)
    hidden = previous.copy()
    hidden[3] |= termios.ICANON | termios.ISIG
    hidden[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(descriptor, termios.TCSAFLUSH, hidden)
    complete = loop.create_future()

    def read():
        if complete.done():
            return
        try:
            value = os.read(descriptor, FRAME_MAX)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as error:
            complete.set_exception(error)
        else:
            complete.set_result(value)

    closing = asyncio.create_task(stopped.wait())
    prompted = False
    try:
        loop.add_reader(descriptor, read)
        os.write(output, label.encode("ascii"))
        prompted = True
        await asyncio.wait((complete, closing), return_when=asyncio.FIRST_COMPLETED)
        if stopped.is_set() or not complete.result():
            raise OperatorCancelled
        value = complete.result()
        if not value.endswith(b"\n"):
            raise ValueError("Enter a value on one private terminal line.")
        try:
            return value[:-1].decode("utf-8")
        except UnicodeError:
            raise ValueError("Enter valid UTF-8 text.") from None
    finally:
        loop.remove_reader(descriptor)
        closing.cancel()
        if not complete.done():
            complete.cancel()
        elif not complete.cancelled():
            complete.exception()
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, previous)
        if prompted:
            os.write(output, b"\n")
        await asyncio.gather(closing, return_exceptions=True)

async def read_credentials(stopped):
    username = await hidden_line("VerySync account (hidden) ", stopped)
    password = await hidden_line("VerySync password (hidden) ", stopped)
    if not username or not password or len(username.encode()) > 512 or len(password.encode()) > 2300:
        raise ValueError("Enter a valid account and password.")
    if any(ord(character) < 32 for character in username) or "\0" in password:
        raise ValueError("Enter a valid account and password.")
    return {"username": username, "password": password}


async def private_call(path, body, timeout=3, before_send=None):
    parent = private_directory(path.parent)
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or path.resolve() != path or info.st_mode & 0o077):
        raise ValueError("The private account service identity is invalid.")
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(parent/path.name),
                                                                        limit=FRAME_MAX), timeout)
    try:
        if before_send is not None:
            before_send()
        writer.write(encode_frame(body))
        await asyncio.wait_for(writer.drain(), timeout)
        return decode_frame(await asyncio.wait_for(reader.readline(), timeout))
    finally:
        writer.close()
        await writer.wait_closed()


class SyntheticAccount:
    def __init__(self, path, recovery):
        self.path, self.recovery = path, recovery

    @staticmethod
    def configuration(profile):
        if type(profile) is not dict or set(profile) != {"socket", "recovery"}:
            raise ValueError("Choose the private synthetic account service.")
        root = private_directory(Path(profile["recovery"]))
        path = Path(profile["socket"])
        private_directory(path.parent)
        return path, root

    @classmethod
    async def open(cls, profile, run, stopped):
        path, root = cls.configuration(profile)
        recovery = root/run
        def check():
            if stopped.is_set():
                raise OperatorCancelled

        values = await read_credentials(stopped)
        recovery.mkdir(mode=0o700)
        try:
            result = await private_call(path, {"kind": "login", **values}, before_send=check)
        except OperatorCancelled:
            recovery.rmdir()
            raise
        finally:
            values.clear()
        session = result.get("session")
        if result.get("ok") is not True or type(session) is not str or not RUN.fullmatch(session):
            raise ValueError("The synthetic account service did not confirm a session.")
        with (recovery/"session").open("x", encoding="ascii") as out:
            out.write(session)
        return cls(path, recovery)

    def token(self):
        path = self.recovery/"session"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("The operator's recovery record is invalid.")
        token = path.read_text(encoding="ascii")
        if not RUN.fullmatch(token):
            raise ValueError("The operator's recovery record is invalid.")
        return token

    async def execute(self, work, before_send):
        before_send()
        reply = await private_call(self.path, {"kind":"inspect", "session":self.token()})
        return {"ok":reply.get("ok") is True, "signed_in":reply.get("ok") is True}

    async def stop(self, _writes, _journal):
        try:
            token = self.token()
            await private_call(self.path, {"kind":"logout", "session":token})
            check = await private_call(self.path, {"kind":"inspect", "session":token})
            if check == {"ok":False,"code":"signed-out"}:
                (self.recovery/"session").unlink()
                self.recovery.rmdir()
                return {"state":"synthetic-session-closed"}
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        return {"state":"pending-confirmation"}

    @classmethod
    async def recover(cls, profile, run):
        if not RUN.fullmatch(run):
            raise ProtocolError("Enter the previous run identifier.")
        path, storage = cls.configuration(profile)
        recovery = storage/run
        if not recovery.exists():
            return {"state":"no-pending-record"}
        private_directory(recovery)
        return await cls(path,recovery).stop([],None)


async def open_backend(target, profile, runtime, run, synthetic, stopped):
    if target == "pro" and synthetic:
        return await SyntheticAccount.open(profile, run, stopped)
    raise ValueError("The requested private service has not been prepared.")


async def recover_synthetic_account(profile, run):
    return await SyntheticAccount.recover(profile,run)
