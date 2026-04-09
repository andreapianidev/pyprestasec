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
            
            # Try to extract affected versions from description
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
    
    def _extract_affected_versions(self, description: str) -> List[str]:
        """Extract affected version info from CVE description"""
        import re
        versions = []
        
        # Common patterns
        patterns = [
            r'version[s]?\s+([\d.]+(?:\s*through\s*[\d.]+)?)',
            r'before\s+([\d.]+)',
            r'([\d.]+)\s+and\s+earlier',
            r'([\d.]+)\s+and\s+prior',
            r'<=?\s*([\d.]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            versions.extend(matches)
        
        return list(set(versions))  # Remove duplicates
    
    def check_version_vulnerable(
        self, 
        detected_version: str, 
        cve: CVEVulnerability
    ) -> bool:
        """
        Check if a detected version is affected by a CVE
        This is a simplified check - real implementation would need proper version comparison
        """
        from packaging import version as pkg_version
        
        # Normalize version
        try:
            detected = pkg_version.parse(detected_version)
        except Exception:
            return False
        
        # Check if version appears in affected versions
        for affected in cve.affected_versions:
            try:
                # Handle ranges like "1.7.0 through 1.7.8"
                if 'through' in affected.lower():
                    parts = affected.lower().split('through')
                    if len(parts) == 2:
                        start = pkg_version.parse(parts[0].strip())
                        end = pkg_version.parse(parts[1].strip())
                        if start <= detected <= end:
                            return True
                
                # Handle "before X.X.X"
                elif affected.lower().startswith('before'):
                    limit = pkg_version.parse(affected[6:].strip())
                    if detected < limit:
                        return True
                
                # Handle exact version or simple comparison
                else:
                    affected_ver = pkg_version.parse(affected.strip())
                    if detected == affected_ver:
                        return True
                        
            except Exception:
                continue
        
        # If no specific version info, assume it might be affected
        # (conservative approach for security)
        if not cve.affected_versions:
            # Check if description mentions the version
            if detected_version in cve.description:
                return True
        
        return False
