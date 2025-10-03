import asyncio
from typing import List

import aiohttp

from .crawler import Crawler
from .checks import run_active_checks, run_passive_checks
from .models import Finding, ScanResult, Target


class Scanner:
    def __init__(self, target: Target, user_agent: str | None = None, max_concurrency: int = 10):
        self.target = target
        self.user_agent = user_agent or "vulnscan/0.1"
        self.max_concurrency = max_concurrency

    async def run(self, enable_active: bool = True) -> ScanResult:
        findings: List[Finding] = []
        timeout = aiohttp.ClientTimeout(total=30)
        headers = {"user-agent": self.user_agent}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            crawler = Crawler(self.target, session, max_concurrency=self.max_concurrency)
            crawled = await crawler.crawl()
            for url in crawled:
                try:
                    async with session.get(url) as resp:
                        text = await resp.text(errors="ignore")
                        set_cookies = resp.headers.getall("set-cookie", []) if hasattr(resp.headers, "getall") else []
                        findings.extend(run_passive_checks(url, resp.headers, set_cookies, text))
                        if enable_active:
                            findings.extend(await run_active_checks(session, url))
                except Exception:
                    # Ignore single-page errors
                    pass
        result = ScanResult(target=self.target, findings=findings, pages_crawled=len(crawled))
        return result
