import asyncio
import re
from urllib.parse import urlparse
from typing import Iterable, Set


def normalize_url(url: str) -> str:
    # Remove fragments and normalize scheme/host casing
    parsed = urlparse(url)
    path = parsed.path or "/"
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


def in_scope(url: str, allowed_hosts: Set[str], include_subdomains: bool) -> bool:
    host = urlparse(url).netloc.lower()
    if include_subdomains:
        return any(host == h or host.endswith("." + h) for h in allowed_hosts)
    return host in allowed_hosts


async def gather_limited(tasks: Iterable[asyncio.Task], limit: int = 50):
    semaphore = asyncio.Semaphore(limit)

    async def _run(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*[_run(t) for t in tasks])


ABSOLUTE_URL_RE = re.compile(r"^https?://", re.I)


def make_absolute_url(base: str, href: str) -> str:
    if ABSOLUTE_URL_RE.search(href):
        return href
    # naive join
    if href.startswith("/"):
        parsed = urlparse(base)
        return f"{parsed.scheme}://{parsed.netloc}{href}"
    if base.endswith("/"):
        return base + href
    return base.rsplit("/", 1)[0] + "/" + href
