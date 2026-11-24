"""Move only this fixture's loopback SSH bytes, with a controlled loss switch."""

import asyncio
from pathlib import Path
import sys


async def transfer(source, target, disconnected):
    while chunk := await source.read(64 * 1024):
        if not disconnected.exists():
            target.write(chunk)
            await target.drain()


async def run(port, disconnected):
    async def bridge(source, reply):
        try:
            upstream, request = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            reply.close()
            return
        try:
            transfers = (asyncio.create_task(transfer(source, request, disconnected)),
                         asyncio.create_task(transfer(upstream, reply, disconnected)))
            _, pending = await asyncio.wait(transfers, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*transfers, return_exceptions=True)
        finally:
            reply.close()
            request.close()

    async with await asyncio.start_server(bridge, "127.0.0.1", 0) as listener:
        print(listener.sockets[0].getsockname()[1], flush=True)
        await listener.serve_forever()


if __name__ == "__main__":
    asyncio.run(run(int(sys.argv[1]), Path(sys.argv[2])))
