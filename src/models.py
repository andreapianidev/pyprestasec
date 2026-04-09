from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class CVEVulnerability:
    """Represents a CVE vulnerability"""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: Optional[float]
    published_date: str
    modified_date: str
    references: List[str]
    affected_versions: List[str]


@dataclass
class PrestaShopVersion:
    """Represents detected PrestaShop version info"""
    version: str
    source: str  # How it was detected (generator meta, README, etc.)
    confidence: str  # high, medium, low


@dataclass
class ScanResult:
    """Represents complete scan result"""
    url: str
    detected_version: Optional[PrestaShopVersion]
    vulnerabilities: List[CVEVulnerability]
    scan_date: datetime
    total_cves: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_report: Optional[object] = None  # SecurityReport from security_checks
    detected_modules: List[object] = field(default_factory=list)  # List[DetectedModule]
