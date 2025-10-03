from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    url: Optional[str] = None
    evidence: Optional[Dict[str, str]] = None
    recommendation: Optional[str] = None


@dataclass
class Target:
    start_url: str
    include_subdomains: bool = False
    allowed_domains: Optional[Set[str]] = None
    max_pages: int = 250


@dataclass
class ScanResult:
    target: Target
    findings: List[Finding] = field(default_factory=list)
    pages_crawled: int = 0

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
