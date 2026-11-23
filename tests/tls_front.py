"""Puts TLS in front of plain test servers, so the gateway's TLS code paths
(implicit TLS, certificate and host name checks) can be exercised locally.

usage: tls_front.py CERT KEY LISTEN_PORT:TARGET_PORT [LISTEN_PORT:TARGET_PORT ...]
"""
import asyncio, ssl, sys

cert, key, pairs = sys.argv[1], sys.argv[2], [tuple(map(int, p.split(":"))) for p in sys.argv[3:]]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


def handler(target):
    async def handle(reader, writer):
        try:
            up_r, up_w = await asyncio.open_connection("127.0.0.1", target)
        except Exception:
            writer.close()
            return
        await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))
    return handle


async def main():
    servers = [await asyncio.start_server(handler(t), "127.0.0.1", l, ssl=ctx) for l, t in pairs]
    print("tls front:", pairs, flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))

asyncio.run(main())
