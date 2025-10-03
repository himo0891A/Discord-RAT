import asyncio
from typing import List
from yarl import URL

from ..models import Finding, Severity


def _finding(id: str, title: str, severity: Severity, url: str, description: str, recommendation: str) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        url=url,
        description=description,
        recommendation=recommendation,
    )


XSS_PROBES = [
    "\"'><svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
]

SQLI_PROBES = [
    "' OR '1'='1",
    """' UNION SELECT NULL--""",
    '" OR "1"="1',
]


async def test_reflected_xss(session, url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = URL(url)
    for payload in XSS_PROBES:
        params = dict(parsed.query)
        if not params:
            continue
        mutated = parsed.with_query({k: payload for k in params})
        async with session.get(str(mutated)) as resp:
            body = await resp.text(errors="ignore")
            if payload in body:
                findings.append(_finding(
                    id="reflected_xss",
                    title="Potential reflected XSS",
                    severity=Severity.HIGH,
                    url=str(mutated),
                    description="Payload reflected unencoded in response.",
                    recommendation="HTML-encode all untrusted data; use CSP; input validation.",
                ))
                break
    return findings


async def test_basic_sqli(session, url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = URL(url)
    for payload in SQLI_PROBES:
        params = dict(parsed.query)
        if not params:
            continue
        mutated = parsed.with_query({k: payload for k in params})
        async with session.get(str(mutated)) as resp:
            text = await resp.text(errors="ignore")
            if any(s in text.lower() for s in [
                "you have an error in your sql syntax",
                "warning: mysql",
                "unclosed quotation mark",
                "sqlite error",
                "postgresql error",
            ]):
                findings.append(_finding(
                    id="sqli_error_based",
                    title="Potential SQL injection (error-based)",
                    severity=Severity.CRITICAL,
                    url=str(mutated),
                    description="Database error observed after payload.",
                    recommendation="Use parameterized queries; ORM; input validation; least privilege.",
                ))
                break
    return findings


async def test_open_redirect(session, url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = URL(url)
    params = dict(parsed.query)
    redirect_param_candidates = {"next", "url", "redirect", "return", "goto"}
    intersect = set(params.keys()) & redirect_param_candidates
    if not intersect:
        return findings
    for param in intersect:
        mutated = parsed.update_query({param: "//evil.example.com"})
        async with session.get(str(mutated), allow_redirects=False) as resp:
            loc = resp.headers.get("location", "")
            if loc.startswith("//evil.example.com") or loc.startswith("http://evil.example.com"):
                findings.append(_finding(
                    id="open_redirect",
                    title="Open redirect via query parameter",
                    severity=Severity.MEDIUM,
                    url=str(mutated),
                    description=f"Server redirects using unvalidated {param}.",
                    recommendation="Validate and whitelist redirect targets; use relative paths only.",
                ))
                break
    return findings


async def run_active_checks(session, url: str) -> List[Finding]:
    # Keep active tests conservative and safe by default
    results = await asyncio.gather(
        test_reflected_xss(session, url),
        test_basic_sqli(session, url),
        test_open_redirect(session, url),
    )
    findings: List[Finding] = []
    for sub in results:
        findings.extend(sub)
    return findings
