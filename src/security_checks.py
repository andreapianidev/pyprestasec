"""
Additional security checks beyond CVE scanning:
  - HTTP Security Headers
  - SSL/TLS Certificate
  - Admin Panel Exposure
  - Overall Risk Score
"""

import requests
import ssl
import socket
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Tuple
from urllib.parse import urlparse


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: Optional[str]
    severity: str          # "good", "warning", "critical"
    recommendation: str


@dataclass
class SSLInfo:
    valid: bool
    issuer: str
    subject: str
    expires: str
    days_remaining: int
    protocol: str
    severity: str          # "good", "warning", "critical"
    details: str


@dataclass
class AdminPanelCheck:
    exposed: bool
    url_found: Optional[str]
    severity: str
    details: str


@dataclass
class SecurityReport:
    headers: List[HeaderCheck]
    ssl_info: Optional[SSLInfo]
    admin_panel: AdminPanelCheck
    risk_score: str        # "A" to "F"
    risk_points: int       # 0-100
    risk_details: List[str]


class SecurityChecker:
    """Performs additional security checks on a PrestaShop site"""

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "desc": "HSTS - Forces HTTPS connections",
            "critical": True,
        },
        "Content-Security-Policy": {
            "desc": "CSP - Prevents XSS and injection attacks",
            "critical": True,
        },
        "X-Frame-Options": {
            "desc": "Prevents clickjacking attacks",
            "critical": False,
        },
        "X-Content-Type-Options": {
            "desc": "Prevents MIME-type sniffing",
            "critical": False,
        },
        "X-XSS-Protection": {
            "desc": "Legacy XSS filter (deprecated but still useful)",
            "critical": False,
        },
        "Referrer-Policy": {
            "desc": "Controls referrer information leakage",
            "critical": False,
        },
        "Permissions-Policy": {
            "desc": "Controls browser feature access",
            "critical": False,
        },
        "X-Permitted-Cross-Domain-Policies": {
            "desc": "Controls Flash/PDF cross-domain access",
            "critical": False,
        },
    }

    ADMIN_PATHS = [
        "/admin", "/admin1", "/admin123", "/backoffice",
        "/bo", "/manager", "/panel", "/administration",
        "/admin-panel", "/ps-admin", "/prestashop-admin",
        "/adminps", "/back-office",
    ]

    def __init__(self, timeout: int = 15, log_callback: Optional[Callable] = None):
        self.timeout = timeout
        self.log = log_callback or (lambda *a: None)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def run_all(self, url: str) -> SecurityReport:
        """Run all security checks"""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        url = url.rstrip("/")

        self.log("info", "Running security headers check...")
        headers = self._check_headers(url)

        self.log("info", "Running SSL/TLS check...")
        ssl_info = self._check_ssl(url)

        self.log("info", "Running admin panel detection...")
        admin = self._check_admin_panel(url)

        self.log("info", "Calculating risk score...")
        score, points, details = self._calculate_risk(headers, ssl_info, admin)

        self.log("success", f"Security checks complete. Risk score: {score} ({points}/100)")

        return SecurityReport(
            headers=headers,
            ssl_info=ssl_info,
            admin_panel=admin,
            risk_score=score,
            risk_points=points,
            risk_details=details,
        )

    # ── HTTP Headers ──────────────────────────────────────────────────

    def _check_headers(self, url: str) -> List[HeaderCheck]:
        results = []
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            response_headers = resp.headers

            for header, info in self.SECURITY_HEADERS.items():
                value = response_headers.get(header)
                present = value is not None

                if present:
                    severity = "good"
                    rec = f"{header} is properly configured."
                else:
                    severity = "critical" if info["critical"] else "warning"
                    rec = f"Missing {header}: {info['desc']}. Add this header to improve security."

                results.append(HeaderCheck(
                    name=header,
                    present=present,
                    value=value,
                    severity=severity,
                    recommendation=rec,
                ))
                status = "present" if present else "MISSING"
                self.log("debug", f"  {header}: {status}")

            # Check for dangerous headers that should NOT be present
            server = response_headers.get("Server", "")
            if server:
                results.append(HeaderCheck(
                    name="Server (info leak)",
                    present=True,
                    value=server,
                    severity="warning",
                    recommendation=f"Server header exposes: '{server}'. Consider removing or masking it.",
                ))

            x_powered = response_headers.get("X-Powered-By", "")
            if x_powered:
                results.append(HeaderCheck(
                    name="X-Powered-By (info leak)",
                    present=True,
                    value=x_powered,
                    severity="warning",
                    recommendation=f"X-Powered-By exposes: '{x_powered}'. Remove this header.",
                ))

        except Exception as e:
            self.log("error", f"Headers check failed: {e}")

        return results

    # ── SSL/TLS ───────────────────────────────────────────────────────

    def _check_ssl(self, url: str) -> Optional[SSLInfo]:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme != "https":
            return SSLInfo(
                valid=False, issuer="N/A", subject="N/A",
                expires="N/A", days_remaining=0, protocol="None (HTTP only)",
                severity="critical",
                details="Site is not using HTTPS! All traffic is unencrypted.",
            )

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(self.timeout)
                s.connect((hostname, port))
                cert = s.getpeercert()
                protocol = s.version()

            # Parse cert info
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            issuer = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))
            subject = subject_dict.get("commonName", "Unknown")

            # Expiry
            expires_str = cert.get("notAfter", "")
            expires_dt = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expires_dt - datetime.utcnow()).days

            # Severity
            if days_remaining < 0:
                severity = "critical"
                details = "SSL certificate has EXPIRED!"
            elif days_remaining < 30:
                severity = "warning"
                details = f"SSL certificate expires in {days_remaining} days. Renew soon."
            else:
                severity = "good"
                details = f"SSL certificate valid for {days_remaining} more days."

            self.log("debug", f"  SSL: {protocol}, expires in {days_remaining}d, issuer: {issuer}")

            return SSLInfo(
                valid=True,
                issuer=issuer,
                subject=subject,
                expires=expires_str,
                days_remaining=days_remaining,
                protocol=protocol,
                severity=severity,
                details=details,
            )

        except ssl.SSLCertVerificationError as e:
            self.log("warning", f"  SSL verification error: {e}")
            return SSLInfo(
                valid=False, issuer="N/A", subject="N/A",
                expires="N/A", days_remaining=0, protocol="Error",
                severity="critical",
                details=f"SSL certificate verification failed: {str(e)[:100]}",
            )
        except Exception as e:
            self.log("warning", f"  SSL check failed: {e}")
            return None

    # ── Admin Panel Detection ─────────────────────────────────────────

    def _check_admin_panel(self, url: str) -> AdminPanelCheck:
        for path in self.ADMIN_PATHS:
            test_url = f"{url}{path}"
            try:
                resp = requests.get(
                    test_url, headers=self.headers,
                    timeout=8, allow_redirects=True
                )
                # Check if we got a login page (not a 404)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(kw in body for kw in ["login", "password", "log in", "authentification", "connexion", "back office"]):
                        self.log("warning", f"  Admin panel found at: {path}")
                        return AdminPanelCheck(
                            exposed=True,
                            url_found=test_url,
                            severity="critical",
                            details=f"Admin login page found at {path}. "
                                    f"This is a common target for brute-force attacks. "
                                    f"Rename your admin folder to a random string.",
                        )
            except Exception:
                continue

        self.log("debug", "  No admin panel found at common paths")
        return AdminPanelCheck(
            exposed=False,
            url_found=None,
            severity="good",
            details="Admin panel not found at common paths. Good — the admin folder appears to be renamed.",
        )

    # ── Risk Score ────────────────────────────────────────────────────

    def _calculate_risk(
        self,
        headers: List[HeaderCheck],
        ssl_info: Optional[SSLInfo],
        admin: AdminPanelCheck,
    ) -> Tuple[str, int, List[str]]:
        """
        Calculate overall security risk score.
        Returns (grade, points 0-100, details list).
        100 = best, 0 = worst.
        """
        points = 100
        details = []

        # Headers scoring
        for h in headers:
            if h.severity == "critical":
                points -= 10
                details.append(f"Missing critical header: {h.name} (-10)")
            elif h.severity == "warning":
                if not h.present:
                    points -= 5
                    details.append(f"Missing header: {h.name} (-5)")
                elif "info leak" in h.name.lower():
                    points -= 3
                    details.append(f"Information leakage: {h.name} (-3)")

        # SSL scoring
        if ssl_info:
            if ssl_info.severity == "critical":
                points -= 25
                details.append(f"SSL issue: {ssl_info.details} (-25)")
            elif ssl_info.severity == "warning":
                points -= 10
                details.append(f"SSL warning: {ssl_info.details} (-10)")
        else:
            points -= 15
            details.append("Could not verify SSL certificate (-15)")

        # Admin panel scoring
        if admin.exposed:
            points -= 20
            details.append("Admin panel exposed at default path (-20)")

        # Clamp
        points = max(0, min(100, points))

        # Grade
        if points >= 90:
            grade = "A"
        elif points >= 75:
            grade = "B"
        elif points >= 60:
            grade = "C"
        elif points >= 40:
            grade = "D"
        else:
            grade = "F"

        return grade, points, details
