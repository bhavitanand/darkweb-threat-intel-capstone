"""A small per-client rate limiter (sliding window, in memory) as pure ASGI middleware.

Why: the API is open (no login) and a few endpoints are expensive (live ingest, text analysis, re-scoring). This
keeps one noisy client from using up the free host. It is per process, which is right for a single worker; use an
edge or gateway limiter if the API is ever scaled out.

Environment:
  RATE_LIMIT_PER_MIN        reads  per client per minute (default 120, 0 turns the limiter off)
  RATE_LIMIT_WRITE_PER_MIN  writes per client per minute (default 20, 0 turns write limiting off)
  TRUST_PROXY=1             take the client address from the first X-Forwarded-For entry (set this behind Render
                            or Vercel; a client can forge the header, so it is a soft limit there)
Only /api/* is limited, and /api/health is never limited so uptime monitors are not throttled.
"""
from __future__ import annotations

import json
import time
from collections import deque

MAX_CLIENTS = 20000


# POST only because the body is text; they change nothing, so they count against the read budget.
READ_LIKE_POSTS = frozenset({"/api/rules/parse"})

class RateLimitMiddleware:
    def __init__(self, app, read_per_min: int = 120, write_per_min: int = 20, trust_proxy: bool = False, clock=time.monotonic):
        self.app = app
        self.limits = {"read": read_per_min, "write": write_per_min}
        self.trust_proxy = trust_proxy
        self.clock = clock
        self.hits: dict[tuple[str, str], deque] = {}

    def _client(self, scope) -> str:
        if self.trust_proxy:
            for k, v in scope.get("headers", []):
                if k == b"x-forwarded-for" and v:
                    first = v.decode("latin-1").split(",")[0].strip()
                    if first:
                        return first
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _allow(self, key: tuple[str, str], limit: int) -> int:
        """Returns 0 if allowed, otherwise the seconds until the client may try again."""
        now = self.clock()
        q = self.hits.setdefault(key, deque())
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= limit:
            return max(1, int(60 - (now - q[0])) + 1)
        q.append(now)
        if len(self.hits) > MAX_CLIENTS:  # bound memory: drop the clients idle the longest
            for k in sorted(self.hits, key=lambda k: self.hits[k][-1] if self.hits[k] else 0)[: MAX_CLIENTS // 10]:
                self.hits.pop(k, None)
        return 0

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] != "http" or not path.startswith("/api/") or path == "/api/health" or scope["method"] == "OPTIONS":
            return await self.app(scope, receive, send)
        kind = "write" if scope["method"] in ("POST", "PUT", "PATCH", "DELETE") else "read"
        if path in READ_LIKE_POSTS:
            kind = "read"  # stores nothing; the website calls it while you type, so it must not use up the write budget
        limit = self.limits[kind]
        if limit > 0:
            wait = self._allow((self._client(scope), kind), limit)
            if wait:
                body = json.dumps({"detail": f"Too many requests. Please wait {wait} seconds and try again."}).encode()
                await send({"type": "http.response.start", "status": 429, "headers": [
                    (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(wait).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)
