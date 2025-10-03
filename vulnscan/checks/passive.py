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


def check_security_headers(url: str, headers) -> List[Finding]:
    findings: List[Finding] = []
    missing = []
    required = {
        "content-security-policy": (Severity.HIGH, "Set a strict Content-Security-Policy with nonces or hashes."),
        "x-frame-options": (Severity.MEDIUM, "Use DENY or SAMEORIGIN to prevent clickjacking."),
        "x-content-type-options": (Severity.MEDIUM, "Set nosniff to prevent MIME sniffing."),
        "referrer-policy": (Severity.LOW, "Set least-privilege policy like no-referrer or strict-origin-when-cross-origin."),
        "strict-transport-security": (Severity.HIGH, "Enable HSTS with includeSubDomains and preload.")
    }
    lc = {k.lower(): v for k, v in headers.items()}
    for name, (sev, rec) in required.items():
        if name not in lc:
            findings.append(_finding(
                id=f"header_missing_{name}",
                title=f"Missing security header: {name}",
                severity=sev,
                url=url,
                description=f"Response is missing {name} header.",
                recommendation=rec,
            ))
    # Weak CSP
    csp = lc.get("content-security-policy")
    if csp and ("unsafe-inline" in csp or "*" in csp):
        findings.append(_finding(
            id="csp_weak",
            title="Weak Content-Security-Policy",
            severity=Severity.MEDIUM,
            url=url,
            description=f"CSP contains unsafe directives: {csp}",
            recommendation="Remove unsafe-inline and wildcards; use nonces/hashes and strict domains.",
        ))
    return findings


def check_cookies(url: str, set_cookie_headers) -> List[Finding]:
    findings: List[Finding] = []
    for cookie in set_cookie_headers:
        lc = cookie.lower()
        if "secure" not in lc:
            findings.append(_finding(
                id="cookie_insecure",
                title="Cookie without Secure flag",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie lacks Secure flag: {cookie}",
                recommendation="Mark cookies Secure to restrict to HTTPS.",
            ))
        if "httponly" not in lc:
            findings.append(_finding(
                id="cookie_httponly",
                title="Cookie without HttpOnly flag",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie lacks HttpOnly: {cookie}",
                recommendation="Use HttpOnly to mitigate XSS stealing cookies.",
            ))
        if "samesite" not in lc:
            findings.append(_finding(
                id="cookie_samesite",
                title="Cookie without SameSite",
                severity=Severity.LOW,
                url=url,
                description=f"Cookie lacks SameSite: {cookie}",
                recommendation="Set SameSite=Lax or Strict to reduce CSRF risk.",
            ))
    return findings


def check_mixed_content(request_url: str, html: str) -> List[Finding]:
    findings: List[Finding] = []
    if not html:
        return findings
    if URL(request_url).scheme != "https":
        return findings
    lowered = html.lower()
    if "http://" in lowered:
        findings.append(_finding(
            id="mixed_content",
            title="Mixed content over HTTPS",
            severity=Severity.MEDIUM,
            url=request_url,
            description="HTTPS page references HTTP resources.",
            recommendation="Serve all subresources over HTTPS or use protocol-relative URLs.",
        ))
    return findings


def run_passive_checks(url: str, response_headers, set_cookie_headers, html: str) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_security_headers(url, response_headers)
    findings += check_cookies(url, set_cookie_headers)
    findings += check_mixed_content(url, html)
    return findings
