import requests
import time
from typing import List, Optional
from datetime import datetime
import os
from src.models import CVEVulnerability


class NVDAPIClient:
    """Client for the National Vulnerability Database (NVD) API"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        self.timeout = int(os.getenv('REQUEST_TIMEOUT', 30))
        self.session = requests.Session()
        
        # Set headers
        self.headers = {
            'User-Agent': 'PyPrestaSec/1.0.0',
            'Accept': 'application/json',
        }
        if self.api_key:
            self.headers['apiKey'] = self.api_key
    
    def search_prestashop_vulnerabilities(
        self, 
        version: Optional[str] = None,
        start_index: int = 0,
        results_per_page: int = 20
    ) -> List[CVEVulnerability]:
        """
        Search for PrestaShop-related CVEs
        
        Args:
            version: Specific PrestaShop version (e.g., "1.7.8")
            start_index: Pagination start index
            results_per_page: Number of results per page
        """
        params = {
            'keywordSearch': 'PrestaShop',
            'startIndex': start_index,
            'resultsPerPage': results_per_page,
        }
        
        # Add version filter if provided
        if version:
            params['keywordSearch'] = f'PrestaShop {version}'
        
        try:
            response = self.session.get(
                self.BASE_URL,
                headers=self.headers,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            
            return self._parse_cves(data)
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVEs: {e}")
            return []
    
    def get_cve_by_id(self, cve_id: str) -> Optional[CVEVulnerability]:
        """Fetch a specific CVE by ID"""
        params = {
            'cveId': cve_id
        }
        
        try:
            response = self.session.get(
                self.BASE_URL,
                headers=self.headers,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            
            cves = self._parse_cves(data)
            return cves[0] if cves else None
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE {cve_id}: {e}")
            return None
    
    def get_all_prestashop_cves(self, max_results: int = 100, log_callback=None) -> List[CVEVulnerability]:
        """Fetch all PrestaShop related CVEs with pagination"""
        log = log_callback or (lambda *a: None)
        all_cves = []
        start_index = 0
        results_per_page = min(20, max_results)  # NVD allows max 20 per request
        page = 1
        
        while len(all_cves) < max_results:
            log("info", f"Fetching CVE page {page} (items {start_index+1}-{start_index+results_per_page})...")
            cves = self.search_prestashop_vulnerabilities(
                start_index=start_index,
                results_per_page=results_per_page
            )
            
            if not cves:
                log("info", f"No more CVEs found. Total pages fetched: {page}")
                break
            
            all_cves.extend(cves)
            log("info", f"Page {page}: got {len(cves)} CVEs (total so far: {len(all_cves)})")
            start_index += results_per_page
            page += 1
            
            # Rate limiting
            if not self.api_key:
                log("debug", "Rate limit: waiting 6s (no API key)...")
                time.sleep(6)
            else:
                time.sleep(0.6)
        
        return all_cves[:max_results]
    
    def _parse_cves(self, data: dict) -> List[CVEVulnerability]:
        """Parse CVE data from NVD API response"""
        vulnerabilities = []
        
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS metrics
            metrics = cve_data.get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0] or {}
            cvss_score = None
            severity = 'UNKNOWN'
            
            if cvss_data:
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore')
                severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
            
            # If no CVSS v3, try v2
            if not cvss_score:
                cvss_v2 = metrics.get('cvssMetricV2', [{}])[0]
                if cvss_v2:
                    cvss_score = cvss_v2.get('cvssData', {}).get('baseScore')
                    # Map V2 score to severity
                    if cvss_score:
                        if cvss_score >= 7.0:
                            severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
            
            # Get dates
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')
            
            # Get references
            refs = cve_data.get('references', [])
            references = [ref.get('url', '') for ref in refs if ref.get('url')]
            
            # Extract affected versions from CPE data + description
            affected_versions = self._extract_cpe_version_ranges(cve_data)
            if not affected_versions:
                affected_versions = self._extract_affected_versions(description)
            
            vuln = CVEVulnerability(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published,
                modified_date=modified,
                references=references,
                affected_versions=affected_versions
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_cpe_version_ranges(self, cve_data: dict) -> List[str]:
        """Extract precise version ranges from NVD CPE configurations.
        
        Returns ranges in normalized format:
          - 'before X.X.X'          (versionEndExcluding)
          - 'through X.X.X'         (versionEndIncluding)
          - 'from X.X.X before Y'   (start + end)
        """
        ranges = []
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if not match.get('vulnerable', False):
                        continue
                    cpe = match.get('criteria', '')
                    # Only care about prestashop CPEs
                    if 'prestashop' not in cpe.lower():
                        continue
                    
                    start_inc = match.get('versionStartIncluding', '')
                    start_exc = match.get('versionStartExcluding', '')
                    end_inc = match.get('versionEndIncluding', '')
                    end_exc = match.get('versionEndExcluding', '')
                    
                    if end_exc:
                        if start_inc:
                            ranges.append(f"{start_inc} through before {end_exc}")
                        else:
                            ranges.append(f"before {end_exc}")
                    elif end_inc:
                        if start_inc:
                            ranges.append(f"{start_inc} through {end_inc}")
                        else:
                            ranges.append(f"through {end_inc}")
                    elif start_inc:
                        ranges.append(f"from {start_inc}")
                    else:
                        # Extract version from CPE URI  cpe:2.3:a:prestashop:prestashop:X.X.X
                        parts = cpe.split(':')
                        if len(parts) >= 6 and parts[5] not in ('*', '-', ''):
                            ranges.append(parts[5])
        
        return ranges

    def _extract_affected_versions(self, description: str) -> List[str]:
        """Extract affected version info from CVE description (fallback)"""
        import re
        versions = []
        
        # Keep prefix (before/through) so check_version_vulnerable can parse them
        patterns = [
            (r'before\s+([\d.]+)', 'before'),
            (r'prior\s+to\s+([\d.]+)', 'before'),
            (r'([\d.]+)\s+and\s+earlier', 'through'),
            (r'([\d.]+)\s+and\s+prior', 'through'),
            (r'<=\s*([\d.]+)', 'through'),
            (r'<\s*([\d.]+)', 'before'),
            (r'version[s]?\s+([\d.]+)\s+through\s+([\d.]+)', 'range'),
        ]
        
        for pattern, kind in patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            for m in matches:
                if kind == 'range':
                    versions.append(f"{m[0]} through {m[1]}")
                elif kind == 'before':
                    versions.append(f"before {m}")
                elif kind == 'through':
                    versions.append(f"through {m}")
        
        return list(set(versions))
    
    def check_version_vulnerable(
        self, 
        detected_version: str, 
        cve: CVEVulnerability
    ) -> bool:
        """Check if a detected version is affected by a CVE using version ranges."""
        from packaging import version as pkg_version
        import re
        
        try:
            detected = pkg_version.parse(detected_version)
        except Exception:
            return False
        
        for affected in cve.affected_versions:
            try:
                a = affected.lower().strip()
                
                # "X.X.X through before Y.Y.Y" (startIncluding + endExcluding)
                m = re.match(r'([\d.]+)\s+through\s+before\s+([\d.]+)', a)
                if m:
                    start = pkg_version.parse(m.group(1))
                    end = pkg_version.parse(m.group(2))
                    if start <= detected < end:
                        return True
                    continue
                
                # "X.X.X through Y.Y.Y" (startIncluding + endIncluding)
                m = re.match(r'([\d.]+)\s+through\s+([\d.]+)', a)
                if m:
                    start = pkg_version.parse(m.group(1))
                    end = pkg_version.parse(m.group(2))
                    if start <= detected <= end:
                        return True
                    continue
                
                # "through Y.Y.Y" (endIncluding, no start)
                m = re.match(r'through\s+([\d.]+)', a)
                if m:
                    end = pkg_version.parse(m.group(1))
                    if detected <= end:
                        return True
                    continue
                
                # "before Y.Y.Y" (endExcluding)
                m = re.match(r'before\s+([\d.]+)', a)
                if m:
                    end = pkg_version.parse(m.group(1))
                    if detected < end:
                        return True
                    continue
                
                # "from X.X.X" (startIncluding, no end = all versions after)
                m = re.match(r'from\s+([\d.]+)', a)
                if m:
                    start = pkg_version.parse(m.group(1))
                    if detected >= start:
                        return True
                    continue
                
                # Exact version match
                affected_ver = pkg_version.parse(a)
                if detected == affected_ver:
                    return True
                    
            except Exception:
                continue
        
        # No version ranges found — check description for version mention
        if not cve.affected_versions:
            desc = cve.description.lower()
            if detected_version in desc or f"prestashop {detected_version}" in desc:
                return True
            # Also match "before X.X.X" in description directly
            for m in re.finditer(r'before\s+([\d.]+)', desc):
                try:
                    if detected < pkg_version.parse(m.group(1)):
                        return True
                except Exception:
                    pass
        
        return False
