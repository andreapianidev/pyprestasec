from datetime import datetime
from typing import List, Optional, Callable
from src.models import ScanResult, PrestaShopVersion, CVEVulnerability
from src.version_detector import VersionDetector
from src.cve_api import NVDAPIClient
from src.security_checks import SecurityChecker
from src.module_detector import ModuleDetector


class PrestaShopScanner:
    """Main scanner for PrestaShop vulnerabilities"""
    
    def __init__(self, api_key: Optional[str] = None, log_callback: Optional[Callable] = None):
        self.log = log_callback or (lambda level, msg: print(f"[{level}] {msg}"))
        self.version_detector = VersionDetector(log_callback=self.log)
        self.cve_client = NVDAPIClient(api_key)
        self.security_checker = SecurityChecker(log_callback=self.log)
        self.module_detector = ModuleDetector(log_callback=self.log)
    
    def scan(
        self, 
        url: str, 
        check_all_cves: bool = True,
        manual_version: Optional[str] = None,
        max_results: int = 100
    ) -> ScanResult:
        """
        Scan a PrestaShop site for vulnerabilities
        
        Args:
            url: The URL of the PrestaShop site
            check_all_cves: If True, fetch all PrestaShop CVEs and filter locally
            manual_version: Manually specified version (skips detection)
            max_results: Max CVEs to fetch
        """
        self.log("info", f"Starting scan of {url}")
        
        # Step 1: Detect version (or use manual)
        detected_version = None
        
        if manual_version and manual_version.strip():
            self.log("info", f"Using manually specified version: {manual_version}")
            detected_version = PrestaShopVersion(
                version=manual_version.strip(),
                source="Manual input",
                confidence="user-provided"
            )
        else:
            self.log("info", "Phase 1/3: Detecting PrestaShop version...")
            detected_version = self.version_detector.detect(url)
            
            if detected_version:
                self.log("success", f"Detected: PrestaShop {detected_version.version} (via {detected_version.source}, {detected_version.confidence} confidence)")
            else:
                self.log("warning", "Could not detect PrestaShop version - will show ALL known CVEs")
        
        # Step 2: Detect installed modules
        self.log("info", "Phase 2/5: Detecting installed modules...")
        try:
            detected_modules = self.module_detector.detect(url)
        except Exception as e:
            self.log("error", f"Module detection failed: {e}")
            detected_modules = []
        
        # Step 3: Fetch relevant CVEs
        self.log("info", "Phase 3/5: Fetching CVE data from NVD API...")
        
        if check_all_cves or not detected_version:
            all_cves = self.cve_client.get_all_prestashop_cves(
                max_results=max_results,
                log_callback=self.log
            )
            self.log("info", f"Retrieved {len(all_cves)} total PrestaShop CVEs from NVD")
            
            if detected_version:
                # If version is approximate (e.g. "1.7.x"), don't filter - show all
                if '.x' in detected_version.version or detected_version.confidence == "low":
                    self.log("warning", f"Version '{detected_version.version}' is approximate - showing ALL CVEs (no filter)")
                    vulnerabilities = all_cves
                else:
                    self.log("info", "Filtering CVEs for detected version...")
                    vulnerabilities = self._filter_vulnerabilities(
                        all_cves, 
                        detected_version.version
                    )
                    self.log("info", f"Filtered to {len(vulnerabilities)} CVEs affecting version {detected_version.version}")
            else:
                vulnerabilities = all_cves
                self.log("info", f"Showing all {len(all_cves)} CVEs (no version filter)")
        else:
            vulnerabilities = self.cve_client.search_prestashop_vulnerabilities(
                version=detected_version.version,
                results_per_page=20
            )
        
        # Step 3: Count by severity
        severity_counts = self._count_by_severity(vulnerabilities)
        
        self.log("success", f"CVE scan complete! Found {len(vulnerabilities)} vulnerabilities")
        self.log("info", f"  CRITICAL: {severity_counts.get('CRITICAL', 0)} | HIGH: {severity_counts.get('HIGH', 0)} | MEDIUM: {severity_counts.get('MEDIUM', 0)} | LOW: {severity_counts.get('LOW', 0)}")
        
        # Match CVEs to detected modules
        if detected_modules:
            self.log("info", "Matching CVEs to detected modules...")
            self._match_modules_to_cves(detected_modules, vulnerabilities)
        
        # Step 5: Security checks (headers, SSL, admin panel)
        self.log("info", "Phase 5/5: Running additional security checks...")
        try:
            security_report = self.security_checker.run_all(url)
        except Exception as e:
            self.log("error", f"Security checks failed: {e}")
            security_report = None
        
        self.log("success", "All scans complete!")
        
        result = ScanResult(
            url=url,
            detected_version=detected_version,
            vulnerabilities=vulnerabilities,
            scan_date=datetime.now(),
            total_cves=len(vulnerabilities),
            critical_count=severity_counts.get('CRITICAL', 0),
            high_count=severity_counts.get('HIGH', 0),
            medium_count=severity_counts.get('MEDIUM', 0),
            low_count=severity_counts.get('LOW', 0),
            security_report=security_report,
            detected_modules=detected_modules,
        )
        
        return result
    
    def _filter_vulnerabilities(
        self, 
        cves: List[CVEVulnerability], 
        version: str
    ) -> List[CVEVulnerability]:
        """Filter CVEs to those likely affecting the given version"""
        filtered = []
        
        for cve in cves:
            if self.cve_client.check_version_vulnerable(version, cve):
                filtered.append(cve)
                continue
            
            if version in cve.description:
                filtered.append(cve)
        
        return filtered
    
    def _match_modules_to_cves(self, modules, cves: List[CVEVulnerability]):
        """Check if any detected module names appear in CVE descriptions"""
        for mod in modules:
            mod_lower = mod.name.lower().replace("_", "").replace("-", "")
            for cve in cves:
                desc_lower = cve.description.lower().replace("_", "").replace("-", "")
                if mod_lower in desc_lower or mod.name.lower() in desc_lower:
                    if cve.cve_id not in mod.cve_ids:
                        mod.cve_ids.append(cve.cve_id)
                        mod.cve_details[cve.cve_id] = {
                            "description": cve.description,
                            "severity": cve.severity,
                            "cvss_score": cve.cvss_score,
                        }
                        mod.has_known_cves = True
            if mod.has_known_cves:
                self.log("warning", f"Module '{mod.name}' has {len(mod.cve_ids)} known CVE(s)!")
    
    def _count_by_severity(self, vulnerabilities: List[CVEVulnerability]) -> dict:
        """Count vulnerabilities by severity level"""
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'UNKNOWN': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity.upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts['UNKNOWN'] += 1
        
        return counts
