import requests
import re
from collections import Counter
from typing import Optional, Callable, List
from bs4 import BeautifulSoup
from src.models import PrestaShopVersion


# ── Module-to-PrestaShop version mapping ──────────────────────────────
# Bundled module versions that ship with specific PrestaShop releases.
# Format: module_name -> {module_version_prefix: ps_version}
MODULE_VERSION_MAP = {
    "ps_facetedsearch": {
        "3.15": "1.7.8.11", "3.14": "1.7.8.10", "3.13": "1.7.8.9",
        "3.12": "1.7.8.8", "3.11": "1.7.8.7", "3.10": "1.7.8.6",
        "3.9": "1.7.8.5", "3.8": "1.7.8.4", "3.7": "1.7.8.3",
        "3.4": "1.7.8.0", "3.3": "1.7.7.8",
    },
    "ps_emailsubscription": {
        "2.8": "1.7.8.8", "2.7": "1.7.8.0", "2.6": "1.7.7.0",
    },
    "contactform": {
        "4.4": "1.7.8.8", "4.3": "1.7.8.0", "4.2": "1.7.7.0",
    },
    "ps_contactinfo": {
        "3.3": "1.7.8.0", "3.2": "1.7.7.0",
    },
    "ps_searchbar": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_shoppingcart": {
        "3.0": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_customersignin": {
        "2.0": "1.7.8.0",
    },
    "ps_wirepayment": {
        "2.2": "1.7.8.8", "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_linklist": {
        "5.0": "1.7.8.0", "4.0": "1.7.7.0", "3.0": "1.7.5.0",
    },
    "ps_mainmenu": {
        "2.3": "1.7.8.0", "2.2": "1.7.7.0",
    },
    "ps_imageslider": {
        "3.1": "1.7.8.0", "3.0": "1.7.6.0",
    },
    "ps_featuredproducts": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_banner": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_socialfollow": {
        "2.3": "1.7.8.0", "2.2": "1.7.7.0",
    },
    "ps_sharebuttons": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_customeraccountlinks": {
        "3.2": "1.7.8.0", "3.1": "1.7.7.0",
    },
    "ps_emailalerts": {
        "3.0": "1.7.8.0", "2.4": "1.7.7.0",
    },
    "ps_dataprivacy": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_customtext": {
        "4.2": "1.7.8.0", "4.1": "1.7.7.0",
    },
    "ps_crossselling": {
        "2.0": "1.7.8.0",
    },
    "ps_currencyselector": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_languageselector": {
        "2.1": "1.7.8.0", "2.0": "1.7.7.0",
    },
    "ps_googleanalytics": {
        "5.0": "1.7.8.8", "4.2": "1.7.8.0", "4.0": "1.7.7.0",
    },
}

# jQuery version -> PS version range
JQUERY_PS_MAP = {
    "3.5.1": "1.7.8",
    "3.4.1": "1.7.7",
    "2.2.3": "1.7.0",
    "2.1.4": "1.7.0",
    "1.11.0": "1.6",
    "1.11.1": "1.6",
}


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
            ("Asset version parameters", self._check_asset_versions),
            ("jQuery fingerprint", self._check_jquery_version),
            ("README / docs files", self._check_readme_file),
            ("JavaScript references", self._check_js_files),
            ("CSS version parameters", self._check_css_files),
            ("Robots.txt patterns", self._check_robots_txt),
            ("Config file probing", self._check_config_paths),
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
    
    def _check_asset_versions(self, url: str) -> Optional[PrestaShopVersion]:
        """Check ALL JS/CSS asset ?v= parameters for PrestaShop version numbers"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')

            version_candidates = Counter()

            # Collect ?v= params from ALL scripts and stylesheets
            for tag in soup.find_all('script', src=True):
                src = tag.get('src', '')
                match = re.search(r'[?&]v=(' + self.VERSION_PATTERN + r')', src)
                if match:
                    v = match.group(1)
                    if self._is_valid_version(v) and len(v.split('.')) >= 3:
                        version_candidates[v] += 1

            for tag in soup.find_all('link', rel='stylesheet'):
                href = tag.get('href', '')
                match = re.search(r'[?&]v=(' + self.VERSION_PATTERN + r')', href)
                if match:
                    v = match.group(1)
                    if self._is_valid_version(v) and len(v.split('.')) >= 3:
                        version_candidates[v] += 1

            if version_candidates:
                # The most frequent version across assets is likely the PS version
                best, count = version_candidates.most_common(1)[0]
                conf = "high" if count >= 5 else "medium" if count >= 2 else "low"
                self.log("info", f"Found version {best} in {count} asset URL(s)")
                return PrestaShopVersion(
                    version=best,
                    source=f"Asset version parameters ({count} assets)",
                    confidence=conf
                )
        except Exception:
            pass
        return None

    def _check_jquery_version(self, url: str) -> Optional[PrestaShopVersion]:
        """Infer PS version range from the bundled jQuery version"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')

            for script in soup.find_all('script', src=True):
                src = script.get('src', '')
                match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', src.lower())
                if match:
                    jq_ver = match.group(1)
                    self.log("info", f"jQuery version: {jq_ver}")
                    # Exact match
                    if jq_ver in JQUERY_PS_MAP:
                        ps_hint = JQUERY_PS_MAP[jq_ver]
                        return PrestaShopVersion(
                            version=f"{ps_hint}.x",
                            source=f"jQuery {jq_ver} fingerprint",
                            confidence="low"
                        )
                    # Range match
                    jq_major = int(jq_ver.split('.')[0])
                    if jq_major >= 3:
                        return PrestaShopVersion(
                            version="1.7.x",
                            source=f"jQuery {jq_ver} (v3+ = PS 1.7+)",
                            confidence="low"
                        )
                    elif jq_major == 2:
                        return PrestaShopVersion(
                            version="1.7.x",
                            source=f"jQuery {jq_ver} (v2 = early PS 1.7)",
                            confidence="low"
                        )
                    elif jq_major == 1:
                        return PrestaShopVersion(
                            version="1.6.x",
                            source=f"jQuery {jq_ver} (v1 = PS 1.6)",
                            confidence="low"
                        )
        except Exception:
            pass
        return None

    def _check_robots_txt(self, url: str) -> Optional[PrestaShopVersion]:
        """Check robots.txt for PrestaShop-specific patterns"""
        try:
            response = requests.get(f"{url}/robots.txt", headers=self.headers, timeout=10)
            if response.status_code == 200:
                text = response.text.lower()
                # PS 1.7+ robots.txt contains these paths
                has_module_paths = 'disallow: /modules/' in text
                has_app = 'disallow: /app/' in text
                has_var = 'disallow: /var/' in text
                # PS 1.6 typically has /tools/ and /classes/
                has_tools = 'disallow: /tools/' in text
                has_classes = 'disallow: /classes/' in text

                if has_app and has_var:
                    return PrestaShopVersion(
                        version="1.7.x",
                        source="robots.txt (/app/ + /var/ paths)",
                        confidence="low"
                    )
                elif has_tools and has_classes and not has_app:
                    return PrestaShopVersion(
                        version="1.6.x",
                        source="robots.txt (/tools/ + /classes/ paths)",
                        confidence="low"
                    )
        except Exception:
            pass
        return None

    def _check_config_paths(self, url: str) -> Optional[PrestaShopVersion]:
        """Probe config file paths to distinguish PS versions"""
        # PS 1.7+ uses /app/config/, PS 1.6 uses /config/
        probes = [
            (f"{url}/app/config/", "1.7.x", "PS 1.7+ config path"),
            (f"{url}/vendor/autoload.php", "1.7.x", "Composer autoload (PS 1.7+)"),
            (f"{url}/bin/console", "8.x", "Symfony console (PS 8+)"),
        ]
        for probe_url, ver_hint, desc in probes:
            try:
                r = requests.head(probe_url, headers=self.headers, timeout=5, allow_redirects=False)
                # 200, 403, or 302 all indicate the path exists
                if r.status_code in (200, 403, 301, 302):
                    self.log("info", f"Found {desc} (HTTP {r.status_code})")
                    return PrestaShopVersion(
                        version=ver_hint,
                        source=desc,
                        confidence="low"
                    )
            except Exception:
                continue
        return None

    def refine_version_from_modules(self, modules, current: Optional[PrestaShopVersion]) -> Optional[PrestaShopVersion]:
        """Use detected module versions to narrow down the PS version.
        
        Cross-references module versions against known PS release bundles.
        This is highly reliable since core modules ship with specific PS releases.
        """
        if not modules:
            return current

        ps_guesses = Counter()

        for mod in modules:
            if not mod.version or mod.name not in MODULE_VERSION_MAP:
                continue
            mapping = MODULE_VERSION_MAP[mod.name]
            # Get major.minor prefix of the module version
            parts = mod.version.split('.')
            prefix = '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]

            if prefix in mapping:
                ps_ver = mapping[prefix]
                ps_guesses[ps_ver] += 1
                self.log("debug", f"Module {mod.name} v{mod.version} -> PS {ps_ver}")

        if not ps_guesses:
            return current

        # Pick the most frequently indicated PS version
        best_ver, votes = ps_guesses.most_common(1)[0]
        total_matches = sum(ps_guesses.values())

        self.log("info", f"Module cross-reference: {total_matches} module(s) suggest PS {best_ver} ({votes} votes)")

        # Only override if we have decent confidence
        if votes >= 2:
            confidence = "high" if votes >= 5 else "medium" if votes >= 3 else "low"
            refined = PrestaShopVersion(
                version=best_ver,
                source=f"Module version cross-reference ({votes} modules matched)",
                confidence=confidence
            )
            # If current version is vague (e.g. "1.7.x"), prefer the refined one
            if not current or '.x' in (current.version or '') or current.confidence == 'low':
                self.log("success", f"Refined version: {best_ver} (from {votes} module matches)")
                return refined
            else:
                self.log("info", f"Keeping existing detection: {current.version} (module hint: {best_ver})")

        return current

    @staticmethod
    def normalize_version(version: str) -> str:
        """Normalize version string to standard format"""
        version = re.sub(r'^[^\d]*', '', version)
        version = re.sub(r'[^\d.].*$', '', version)
        
        parts = version.split('.')
        while len(parts) < 2:
            parts.append('0')
        
        return '.'.join(parts[:3])
