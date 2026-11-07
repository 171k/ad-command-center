"""In-process pub/sub for Server-Sent Events (live cross-session sync).

Four browser sessions subscribe to one event stream. When any session mutates
shared state (findings, offenses, services), the backend publishes a small JSON
message so other sessions update without a manual refresh. Bounded per-client
queues drop oldest messages under pressure rather than growing unbounded.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

_subscribers: set[asyncio.Queue] = set()
_MAX_QUEUE = 100


async def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def publish(topic: str, data: dict[str, Any] | None = None) -> None:
    msg = json.dumps({"topic": topic, "data": data or {}})
    for q in list(_subscribers):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            try:
                q.get_nowait()  # drop oldest
                q.put_nowait(msg)
            except Exception:
                pass


def subscriber_count() -> int:
    return len(_subscribers)
