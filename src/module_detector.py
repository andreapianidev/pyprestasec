"""
PrestaShop Module Detector
Discovers installed modules by probing common module paths and parsing HTML source.
"""

import re
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Set
from urllib.parse import urljoin


@dataclass
class DetectedModule:
    """A PrestaShop module found on the target site"""
    name: str
    version: Optional[str] = None
    source: str = ""  # how it was detected
    path: str = ""    # URL path where found
    has_known_cves: bool = False
    cve_ids: List[str] = field(default_factory=list)
    cve_details: dict = field(default_factory=dict)  # {cve_id: {description, severity, cvss_score}}


# Common PrestaShop modules to probe (most popular + most attacked)
COMMON_MODULES = [
    # Payment
    "ps_checkout", "ps_wirepayment", "ps_cashondelivery", "paypal",
    "stripe_official", "mollie", "ps_payhere",
    # Shipping
    "ps_deliverytime", "ps_carriercomparison",
    # SEO / Marketing
    "ps_googleanalytics", "ps_emailsubscription", "ps_socialfollow",
    "ps_sharebuttons", "mailalert", "ps_dataprivacy",
    # Catalog / Products
    "ps_facetedsearch", "blocklayered", "ps_categoryproducts",
    "ps_bestsellers", "ps_newproducts", "ps_specials",
    "ps_featuredproducts", "ps_crossselling", "ps_productinfo",
    # Navigation / Theme
    "ps_mainmenu", "ps_searchbar", "ps_customersignin",
    "ps_languageselector", "ps_currencyselector", "ps_banner",
    "ps_imageslider", "ps_customtext", "ps_contactinfo",
    "ps_linklist", "ps_brandlist", "ps_supplierlist",
    # Customer
    "ps_customeraccountlinks", "ps_shoppingcart", "ps_wishlist",
    # Forms / Contact
    "contactform", "ps_emailalerts",
    # Admin / Stats
    "statsdata", "statssearch", "statsregistrations",
    # Security-sensitive / commonly exploited
    "columnadverts", "homeslider", "simpleslideshow",
    "productpageadverts", "cartabandonmentpro", "advancedslider",
    "sampledatainstall", "paborrowmyideas",
    "desaborrowmyideas", "sooaborrowmyideas",
    "bamaborrowmyideas", "ndborrow",
    "jmsblog", "jmsslider", "ph_simpleblog",
    "smartblog", "prestablog",
    # File managers (high risk)
    "filemanager", "elfinder", "tinymce",
    "responsivefilemanager",
]


class ModuleDetector:
    """Detects installed PrestaShop modules"""

    def __init__(self, timeout: int = 8, log_callback: Optional[Callable] = None):
        self.timeout = timeout
        self.log = log_callback or (lambda *a: None)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def detect(self, url: str) -> List[DetectedModule]:
        """Run all module detection methods and return unique results"""
        url = url.rstrip("/")
        found: dict[str, DetectedModule] = {}  # name -> module

        # Method 1: Parse HTML source for module references
        self.log("info", "Module detection: analyzing HTML source...")
        html_modules = self._detect_from_html(url)
        for m in html_modules:
            if m.name not in found:
                found[m.name] = m

        # Method 2: Probe common module paths
        self.log("info", f"Module detection: probing {len(COMMON_MODULES)} known module paths...")
        probed = self._probe_module_paths(url)
        for m in probed:
            if m.name not in found:
                found[m.name] = m

        modules = sorted(found.values(), key=lambda m: m.name)
        self.log("success", f"Module detection complete: {len(modules)} modules found")
        return modules

    def _detect_from_html(self, url: str) -> List[DetectedModule]:
        """Parse homepage HTML for module references in CSS/JS/HTML"""
        modules: dict[str, DetectedModule] = {}
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            html = resp.text

            # Pattern 1: /modules/<name>/ in URLs (CSS, JS, images)
            pattern = r'/modules/([a-zA-Z0-9_-]+)/'
            matches = re.findall(pattern, html)
            for mod_name in matches:
                mod_name = mod_name.lower().strip()
                if mod_name and len(mod_name) > 2 and mod_name not in modules:
                    modules[mod_name] = DetectedModule(
                        name=mod_name,
                        source="HTML source",
                        path=f"/modules/{mod_name}/",
                    )

            # Pattern 2: Try to find versions in query strings like ?v=1.2.3 or &version=1.2.3
            versioned = re.findall(
                r'/modules/([a-zA-Z0-9_-]+)/[^"\']*?(?:\?|&)v(?:ersion)?=(\d+\.\d+(?:\.\d+)*)',
                html
            )
            for mod_name, version in versioned:
                mod_name = mod_name.lower().strip()
                if mod_name in modules:
                    modules[mod_name].version = version
                else:
                    modules[mod_name] = DetectedModule(
                        name=mod_name,
                        version=version,
                        source="HTML source (versioned URL)",
                        path=f"/modules/{mod_name}/",
                    )

            # Pattern 3: data-module attributes
            data_modules = re.findall(r'data-module="([a-zA-Z0-9_-]+)"', html)
            for mod_name in data_modules:
                mod_name = mod_name.lower().strip()
                if mod_name and mod_name not in modules:
                    modules[mod_name] = DetectedModule(
                        name=mod_name,
                        source="data-module attribute",
                        path="",
                    )

            self.log("info", f"  Found {len(modules)} modules in HTML source")

        except Exception as e:
            self.log("warning", f"  HTML analysis failed: {str(e)[:80]}")

        return list(modules.values())

    def _probe_module_paths(self, url: str) -> List[DetectedModule]:
        """Probe known module directory paths"""
        modules = []
        checked = 0
        found = 0

        for mod_name in COMMON_MODULES:
            checked += 1
            # Check if module directory is accessible
            test_url = f"{url}/modules/{mod_name}/"
            try:
                resp = requests.head(
                    test_url,
                    headers=self.headers,
                    timeout=4,
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    found += 1
                    # Try to read config.xml for version info
                    version = self._try_read_version(url, mod_name)
                    modules.append(DetectedModule(
                        name=mod_name,
                        version=version,
                        source="directory probe",
                        path=f"/modules/{mod_name}/",
                    ))
                    ver_str = f" v{version}" if version else ""
                    self.log("info", f"  Found: {mod_name}{ver_str}")
            except Exception:
                pass

            # Log progress every 20 modules
            if checked % 20 == 0:
                self.log("debug", f"  Probed {checked}/{len(COMMON_MODULES)} modules ({found} found)...")

        return modules

    def _try_read_version(self, url: str, mod_name: str) -> Optional[str]:
        """Try to read module version from config.xml or logo metadata"""
        config_url = f"{url}/modules/{mod_name}/config.xml"
        try:
            resp = requests.get(config_url, headers=self.headers, timeout=4, allow_redirects=True)
            if resp.status_code == 200 and "<module>" in resp.text.lower():
                ver_match = re.search(r'<version>\s*<!\[CDATA\[([^\]]+)\]\]>\s*</version>', resp.text)
                if ver_match:
                    return ver_match.group(1).strip()
                ver_match = re.search(r'<version>([^<]+)</version>', resp.text)
                if ver_match:
                    return ver_match.group(1).strip()
        except Exception:
            pass
        return None
