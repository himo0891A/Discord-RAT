import asyncio
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup

from .models import Target
from .utils import in_scope, make_absolute_url, normalize_url


class Crawler:
    def __init__(self, target: Target, session: aiohttp.ClientSession, max_concurrency: int = 10):
        self.target = target
        self.session = session
        self.max_concurrency = max_concurrency
        self.visited: Set[str] = set()
        self.to_visit: asyncio.Queue[str] = asyncio.Queue()

        parsed = urlparse(target.start_url)
        base_host = parsed.netloc.lower()
        self.allowed_hosts: Set[str] = {base_host}
        if target.allowed_domains:
            self.allowed_hosts |= {h.lower() for h in target.allowed_domains}

    async def crawl(self) -> List[str]:
        await self.to_visit.put(normalize_url(self.target.start_url))
        urls: List[str] = []
        workers = [asyncio.create_task(self._worker(urls)) for _ in range(self.max_concurrency)]
        await self.to_visit.join()
        for w in workers:
            w.cancel()
        return urls

    async def _worker(self, urls_accumulator: List[str]) -> None:
        while True:
            try:
                url = await self.to_visit.get()
            except asyncio.CancelledError:
                return
            if url in self.visited or len(self.visited) >= self.target.max_pages:
                self.to_visit.task_done()
                continue
            self.visited.add(url)
            try:
                html, content_type, resp = await self._fetch(url)
                urls_accumulator.append(url)
                if content_type and "text/html" in content_type and html:
                    for href in self._extract_links(url, html):
                        if href not in self.visited and in_scope(href, self.allowed_hosts, self.target.include_subdomains):
                            await self.to_visit.put(href)
            finally:
                self.to_visit.task_done()

    async def _fetch(self, url: str) -> Tuple[str, str, aiohttp.ClientResponse]:
        async with self.session.get(url, allow_redirects=True) as resp:
            content_type = resp.headers.get("content-type", "")
            if "text/html" in content_type:
                text = await resp.text(errors="ignore")
            else:
                # Read small bodies to avoid connection reuse issues
                await resp.read()
                text = ""
            return text, content_type, resp

    def _extract_links(self, base_url: str, html: str) -> Set[str]:
        soup = BeautifulSoup(html, "html.parser")
        links: Set[str] = set()
        for tag in soup.find_all(["a", "link", "script", "img"]):
            href = tag.get("href") or tag.get("src")
            if not href:
                continue
            abs_url = normalize_url(make_absolute_url(base_url, href))
            links.add(abs_url)
        return links
