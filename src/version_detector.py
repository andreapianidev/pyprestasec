import requests
import re
from typing import Optional, Callable, List
from bs4 import BeautifulSoup
from src.models import PrestaShopVersion


class VersionDetector:
    """Detects PrestaShop version from various sources"""
    
    VERSION_PATTERN = r'(\d+\.\d+(?:\.\d+)*)'
    
    def __init__(self, timeout: int = 30, log_callback: Optional[Callable] = None):
        self.timeout = timeout
        self.log = log_callback or (lambda *a, **kw: None)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    
    def detect(self, url: str) -> Optional[PrestaShopVersion]:
        """Try multiple methods to detect PrestaShop version"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        url = url.rstrip('/')
        
        methods = [
            ("Generator meta tag", self._check_generator_meta),
            ("HTTP headers", self._check_prestashop_header),
            ("prestashop.js fingerprint", self._check_prestashop_js),
            ("README / docs files", self._check_readme_file),
            ("JavaScript references", self._check_js_files),
            ("CSS version parameters", self._check_css_files),
            ("PrestaShop core files", self._check_core_files),
        ]
        
        for name, method in methods:
            try:
                self.log("info", f"Trying detection method: {name}...")
                result = method(url)
                if result and self._is_valid_version(result.version):
                    self.log("success", f"Version found via {name}: {result.version}")
                    return result
                else:
                    self.log("debug", f"No version found via {name}")
            except requests.exceptions.Timeout:
                self.log("warning", f"Timeout on {name}")
            except requests.exceptions.ConnectionError:
                self.log("error", f"Connection error on {name}")
            except Exception as e:
                self.log("debug", f"Method {name} failed: {str(e)[:80]}")
                continue
        
        self.log("warning", "Could not detect version with any method")
        return None
    
    def _is_valid_version(self, version: str) -> bool:
        """Validate that a version string looks like a real PrestaShop version"""
        if not version or not re.match(r'^\d+\.\d+', version):
            return False
        parts = version.split('.')
        try:
            major = int(parts[0])
            return major in (1, 8, 9)  # Known PrestaShop major versions
        except (ValueError, IndexError):
            return False
    
    def _check_generator_meta(self, url: str) -> Optional[PrestaShopVersion]:
        """Check for generator meta tag in homepage"""
        response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        meta = soup.find('meta', attrs={'name': 'generator'})
        if meta and 'prestashop' in meta.get('content', '').lower():
            content = meta['content']
            match = re.search(r'PrestaShop\s*' + self.VERSION_PATTERN, content, re.IGNORECASE)
            if match:
                return PrestaShopVersion(
                    version=match.group(1),
                    source="Generator meta tag",
                    confidence="high"
                )
        
        # Check HTML comments
        html_text = response.text
        comment_matches = re.findall(r'<!--.*?-->', html_text, re.DOTALL)
        for comment in comment_matches:
            if 'prestashop' in comment.lower():
                match = re.search(r'[Pp]resta[Ss]hop\s*' + self.VERSION_PATTERN, comment)
                if match:
                    return PrestaShopVersion(
                        version=match.group(1),
                        source="HTML comment",
                        confidence="medium"
                    )
        
        # Check page source for prestashop version patterns
        ps_patterns = [
            r'prestashop_version\s*[=:]\s*["\']?' + self.VERSION_PATTERN,
            r'ps_version\s*[=:]\s*["\']?' + self.VERSION_PATTERN,
            r'"version"\s*:\s*"' + self.VERSION_PATTERN + r'"',
        ]
        for pattern in ps_patterns:
            match = re.search(pattern, html_text, re.IGNORECASE)
            if match:
                return PrestaShopVersion(
                    version=match.group(1),
                    source="Page source pattern",
                    confidence="medium"
                )
        
        return None
    
    def _check_prestashop_header(self, url: str) -> Optional[PrestaShopVersion]:
        """Check HTTP headers for PrestaShop version"""
        response = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
        
        headers_to_check = ['X-PrestaShop-Version', 'X-Powered-By', 'Server', 'X-Powered-CMS']
        for header in headers_to_check:
            value = response.headers.get(header, '')
            if 'prestashop' in value.lower():
                match = re.search(r'[Pp]resta[Ss]hop[/-]?\s*' + self.VERSION_PATTERN, value)
                if match:
                    return PrestaShopVersion(
                        version=match.group(1),
                        source=f"HTTP header: {header}",
                        confidence="high"
                    )
        
        # Check Powered-By even without "prestashop" keyword
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            match = re.search(self.VERSION_PATTERN, powered_by)
            if match and 'php' not in powered_by.lower():
                return PrestaShopVersion(
                    version=match.group(1),
                    source=f"HTTP header: X-Powered-By ({powered_by})",
                    confidence="low"
                )
        
        return None
    
    def _check_prestashop_js(self, url: str) -> Optional[PrestaShopVersion]:
        """Check prestashop.js or theme.js for version"""
        js_paths = [
            f"{url}/js/prestashop.js",
            f"{url}/themes/default-bootstrap/js/global.js",  # PS 1.6
            f"{url}/themes/classic/assets/js/theme.js",      # PS 1.7+
        ]
        
        for js_url in js_paths:
            try:
                response = requests.get(js_url, headers=self.headers, timeout=10)
                if response.status_code == 200 and len(response.text) > 50:
                    match = re.search(r'prestashop.*?' + self.VERSION_PATTERN, response.text[:5000], re.IGNORECASE)
                    if match:
                        return PrestaShopVersion(
                            version=match.group(1),
                            source=f"JS file: {js_url.split('/')[-1]}",
                            confidence="medium"
                        )
            except Exception:
                continue
        
        return None
    
    def _check_readme_file(self, url: str) -> Optional[PrestaShopVersion]:
        """Check for README files that might contain version info"""
        readme_urls = [
            f"{url}/README.md",
            f"{url}/docs/readme_en.txt",
            f"{url}/Install_PrestaShop.html",
            f"{url}/CHANGELOG.txt",
        ]
        
        for readme_url in readme_urls:
            try:
                response = requests.get(readme_url, headers=self.headers, timeout=10)
                if response.status_code == 200 and len(response.text) > 10:
                    # Look specifically for PrestaShop version pattern
                    match = re.search(r'[Pp]resta[Ss]hop\s*' + self.VERSION_PATTERN, response.text[:3000])
                    if match:
                        return PrestaShopVersion(
                            version=match.group(1),
                            source=f"File: {readme_url.split('/')[-1]}",
                            confidence="medium"
                        )
                    # Fallback: generic version pattern (less reliable)
                    match = re.search(r'[Vv]ersion\s*:?\s*' + self.VERSION_PATTERN, response.text[:3000])
                    if match:
                        return PrestaShopVersion(
                            version=match.group(1),
                            source=f"File: {readme_url.split('/')[-1]}",
                            confidence="low"
                        )
            except Exception:
                continue
        
        return None
    
    def _check_js_files(self, url: str) -> Optional[PrestaShopVersion]:
        """Check JavaScript files for version indicators"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check script src URLs
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '')
                if 'prestashop' in src.lower():
                    match = re.search(r'[Pp]resta[Ss]hop[/-]?' + self.VERSION_PATTERN, src)
                    if match:
                        return PrestaShopVersion(
                            version=match.group(1),
                            source="JavaScript file reference",
                            confidence="medium"
                        )
            
            # Check inline scripts
            inline_scripts = soup.find_all('script', src=False)
            for script in inline_scripts:
                text = script.string or ''
                if not text:
                    continue
                
                # Look for prestashop config objects
                ps_patterns = [
                    r'prestashop\s*[=.{].*?' + self.VERSION_PATTERN,
                    r'ps_version\s*[:=]\s*["\']' + self.VERSION_PATTERN,
                    r'prestashop_version\s*[:=]\s*["\']' + self.VERSION_PATTERN,
                ]
                for pattern in ps_patterns:
                    match = re.search(pattern, text[:3000], re.IGNORECASE | re.DOTALL)
                    if match:
                        return PrestaShopVersion(
                            version=match.group(1),
                            source="Inline JavaScript",
                            confidence="medium"
                        )
        except Exception:
            pass
        
        return None
    
    def _check_css_files(self, url: str) -> Optional[PrestaShopVersion]:
        """Check CSS files for version indicators"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            links = soup.find_all('link', rel='stylesheet')
            for link in links:
                href = link.get('href', '')
                if 'prestashop' in href.lower() or 'theme' in href.lower():
                    match = re.search(r'[?&]v=' + self.VERSION_PATTERN, href)
                    if match:
                        return PrestaShopVersion(
                            version=match.group(1),
                            source="CSS file version parameter",
                            confidence="low"
                        )
        except Exception:
            pass
        
        return None
    
    def _check_core_files(self, url: str) -> Optional[PrestaShopVersion]:
        """Check for known PrestaShop core files to infer version range"""
        # PS 1.7+ has /themes/core.js, PS 1.6 has /js/tools.js
        markers = {
            f"{url}/themes/core.js": ("1.7", "high"),
            f"{url}/js/tools.js": ("1.6", "low"),
            f"{url}/modules/ps_facetedsearch/": ("1.7", "low"),
            f"{url}/modules/blocklayered/": ("1.6", "low"),
        }
        
        for test_url, (version_hint, confidence) in markers.items():
            try:
                response = requests.head(test_url, headers=self.headers, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    self.log("info", f"Found {test_url.split('/')[-1]} - suggests PS {version_hint}.x")
                    # This only gives major version hint, not exact - return as low confidence
                    return PrestaShopVersion(
                        version=f"{version_hint}.x",
                        source=f"Core file fingerprint: {test_url.split('/')[-1]}",
                        confidence="low"
                    )
            except Exception:
                continue
        
        return None
    
    @staticmethod
    def normalize_version(version: str) -> str:
        """Normalize version string to standard format"""
        version = re.sub(r'^[^\d]*', '', version)
        version = re.sub(r'[^\d.].*$', '', version)
        
        parts = version.split('.')
        while len(parts) < 2:
            parts.append('0')
        
        return '.'.join(parts[:3])
