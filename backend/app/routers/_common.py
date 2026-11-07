from __future__ import annotations

from fastapi import Query


def paginate(page: int, size: int) -> tuple[int, int]:
    page = max(1, page)
    size = min(max(1, size), 200)
    return size, (page - 1) * size


PageQuery = dict(
    page=Query(1, ge=1),
    size=Query(50, ge=1, le=200),
)
