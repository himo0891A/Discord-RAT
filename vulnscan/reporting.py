from typing import List
import json

from .models import Finding, ScanResult


def to_console(result: ScanResult) -> str:
    lines: List[str] = []
    lines.append(f"Target: {result.target.start_url}")
    lines.append(f"Pages crawled: {result.pages_crawled}")
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines.append("Findings:")
    for f in result.findings:
        lines.append(f"- [{f.severity.upper()}] {f.title} ({f.id})")
        if f.url:
            lines.append(f"  at: {f.url}")
        if f.evidence:
            lines.append(f"  evidence: {json.dumps(f.evidence) }")
        if f.recommendation:
            lines.append(f"  fix: {f.recommendation}")
    return "\n".join(lines)


def to_json(result: ScanResult) -> str:
    return json.dumps({
        "target": result.target.start_url,
        "pages_crawled": result.pages_crawled,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "url": f.url,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            } for f in result.findings
        ]
    }, indent=2)
