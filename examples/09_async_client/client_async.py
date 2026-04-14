"""Async SOAP client — fan out 5 concurrent calls with asyncio.gather.

``SoapClient.call_async`` is the awaitable counterpart to ``call``.  It uses
the same WSDL bootstrap and signature cache; the only difference is the
underlying transport awaits httpx's async client.

Run:
    uv run python examples/09_async_client/server.py &
    uv run python examples/09_async_client/client_async.py
"""
from __future__ import annotations

import asyncio
import time

from soapbar.client.client import SoapClient


async def main() -> None:
    client = SoapClient(wsdl_url="http://127.0.0.1:8009/soap?wsdl")

    # Five 200 ms server-side delays would take 1 s sequentially.  With
    # asyncio.gather they overlap on the wire even though each individual
    # request still takes 200 ms server-side.
    pairs = [(1, 2), (3, 4), (5, 6), (7, 8), (9, 10)]

    t0 = time.perf_counter()
    results = await asyncio.gather(
        *(client.call_async("slow_add", a=a, b=b) for a, b in pairs)
    )
    elapsed = time.perf_counter() - t0

    for (a, b), r in zip(pairs, results, strict=True):
        print(f"  slow_add({a}, {b}) = {r}")
    print(f"\n5 concurrent calls finished in {elapsed:.2f}s "
          f"(serial would be ~1.0s)")


if __name__ == "__main__":
    asyncio.run(main())
