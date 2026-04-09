"""
PDF / JSON / CSV report generation with professional layout.
All exports include credits for Andrea Piani.
"""

import json
import csv
import io
from datetime import datetime
from fpdf import FPDF

CREDITS_LINE = "Created by Andrea Piani - www.andreapiani.com - andreapiani.dev@gmail.com"
CREDITS_SHORT = "Andrea Piani | www.andreapiani.com | andreapiani.dev@gmail.com"


def _safe(text: str) -> str:
    """Replace Unicode chars that Helvetica can't render with ASCII equivalents"""
    replacements = {
        '\u2014': '-',   # em dash
        '\u2013': '-',   # en dash
        '\u2018': "'",   # left single quote
        '\u2019': "'",   # right single quote
        '\u201c': '"',   # left double quote
        '\u201d': '"',   # right double quote
        '\u2026': '...',  # ellipsis
        '\u2022': '-',   # bullet
        '\u00a0': ' ',   # non-breaking space
        '\u00e9': 'e',   # e-acute (common in French PS descriptions)
        '\u00e8': 'e',   # e-grave
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Fallback: strip any remaining non-latin1 chars
    return text.encode('latin-1', errors='replace').decode('latin-1')

SEVERITY_COLORS = {
    "CRITICAL": (220, 38, 38),
    "HIGH": (234, 88, 12),
    "MEDIUM": (202, 138, 4),
    "LOW": (22, 163, 74),
    "UNKNOWN": (107, 114, 128),
}


# ── PDF Report ────────────────────────────────────────────────────────

class VulnReportPDF(FPDF):
    """Professional vulnerability report PDF"""

    def __init__(self, result):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.result = result
        self.set_auto_page_break(auto=True, margin=25)

    # ── header / footer on every page ──
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 6, _safe("PyPrestaSec - PrestaShop Vulnerability Report"), align="L")
        self.ln(8)
        self.set_draw_color(220, 220, 220)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-20)
        self.set_draw_color(220, 220, 220)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(140, 140, 140)
        self.cell(0, 5, _safe(CREDITS_LINE), align="L")
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}", align="R")

    # ── build report ──
    def build(self) -> bytes:
        r = self.result
        self.alias_nb_pages()
        self.add_page()

        # ── Title ──
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(223, 0, 103)
        self.cell(0, 12, "Vulnerability Assessment Report", ln=True)
        self.ln(2)

        # ── Meta info ──
        self.set_font("Helvetica", "", 10)
        self.set_text_color(60, 60, 60)
        self._meta_row("Target URL:", _safe(r.url))
        ver = r.detected_version
        if ver:
            self._meta_row("PrestaShop Version:", _safe(f"{ver.version}  (detected via {ver.source}, {ver.confidence} confidence)"))
        else:
            self._meta_row("PrestaShop Version:", "Not detected")
        self._meta_row("Scan Date:", r.scan_date.strftime("%Y-%m-%d %H:%M:%S"))
        self._meta_row("Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.ln(6)

        # ── Executive Summary ──
        self._section_title("Executive Summary")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        total = r.total_cves
        summary_text = _safe(
            f"A total of {total} known vulnerabilities were identified for the target PrestaShop installation. "
            f"Of these, {r.critical_count} are rated CRITICAL, {r.high_count} HIGH, "
            f"{r.medium_count} MEDIUM, and {r.low_count} LOW severity. "
        )
        if r.critical_count > 0:
            summary_text += "Immediate action is strongly recommended to address the critical vulnerabilities."
        elif r.high_count > 0:
            summary_text += "It is recommended to address high-severity issues as soon as possible."
        else:
            summary_text += "No critical issues were found, but all vulnerabilities should be reviewed."
        self.multi_cell(0, 5, summary_text)
        self.ln(4)

        # ── Severity Summary Table ──
        self._section_title("Severity Breakdown")
        self._severity_table(r)
        self.ln(6)

        # ── Vulnerability Details ──
        self._section_title(f"Vulnerability Details ({total} total)")
        self.ln(2)

        for i, v in enumerate(r.vulnerabilities, 1):
            self._render_vuln(i, v)

        # ── Installed Modules ──
        if r.detected_modules:
            self.add_page()
            self._render_modules_section(r.detected_modules)

        # ── Security Assessment (if available) ──
        if r.security_report:
            self.add_page()
            self._render_security_section(r.security_report)

        # ── Final page: Credits & Disclaimer ──
        self.add_page()
        self._section_title("Disclaimer")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(80, 80, 80)
        self.multi_cell(0, 5,
            "This report is provided for informational and security research purposes only. "
            "The vulnerability data is sourced from the National Vulnerability Database (NVD) maintained by NIST. "
            "While every effort has been made to ensure accuracy, the information may not be exhaustive. "
            "Always verify findings and consult with a qualified security professional before making changes "
            "to production systems. The author assumes no liability for actions taken based on this report."
        )
        self.ln(10)

        self._section_title("About")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(60, 60, 60)
        self.multi_cell(0, 6,
            "This report was generated by PyPrestaSec, a PrestaShop vulnerability scanner.\n\n"
            f"Created by Andrea Piani\n"
            f"Website: www.andreapiani.com\n"
            f"Email: andreapiani.dev@gmail.com\n\n"
            f"For inquiries about security assessments, consulting, or custom reports, "
            f"please reach out via email or visit the website above."
        )

        return self.output()

    # ── helpers ──
    def _meta_row(self, label: str, value: str):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(42, 6, label)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(30, 30, 30)
        self.cell(0, 6, value, ln=True)

    def _section_title(self, title: str):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(223, 0, 103)
        self.cell(0, 8, _safe(title), ln=True)
        self.set_draw_color(223, 0, 103)
        self.line(10, self.get_y(), 80, self.get_y())
        self.ln(4)

    def _severity_table(self, r):
        col_w = 38
        self.set_font("Helvetica", "B", 10)

        headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"]
        counts = [r.critical_count, r.high_count, r.medium_count, r.low_count, r.total_cves]
        colors = [
            (220, 38, 38), (234, 88, 12), (202, 138, 4),
            (22, 163, 74), (99, 102, 241),
        ]

        # Header row
        for h, c in zip(headers, colors):
            self.set_fill_color(*c)
            self.set_text_color(255, 255, 255)
            self.cell(col_w, 8, h, border=0, fill=True, align="C")
        self.ln()

        # Value row
        self.set_font("Helvetica", "B", 16)
        for count, c in zip(counts, colors):
            self.set_fill_color(min(c[0]+40, 255), min(c[1]+40, 255), min(c[2]+40, 255))
            self.set_text_color(*c)
            self.cell(col_w, 10, str(count), border=0, fill=True, align="C")
        self.ln()

    def _render_vuln(self, idx: int, v):
        # Check if we need a new page (at least 40mm needed)
        if self.get_y() > 240:
            self.add_page()

        sev_color = SEVERITY_COLORS.get(v.severity, (107, 114, 128))

        # CVE header bar
        self.set_fill_color(*sev_color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 10)
        score_str = f"CVSS {v.cvss_score}" if v.cvss_score else "CVSS N/A"
        self.cell(0, 7, _safe(f"  {idx}. {v.cve_id}  -  {v.severity}  ({score_str})"), ln=True, fill=True)

        # Description
        self.set_text_color(50, 50, 50)
        self.set_font("Helvetica", "", 9)
        desc = v.description[:500] + ("..." if len(v.description) > 500 else "")
        self.multi_cell(0, 4.5, _safe(desc))

        # Meta line
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        pub = v.published_date[:10] if v.published_date else "N/A"
        aff = ", ".join(v.affected_versions[:3]) if v.affected_versions else "N/A"
        self.cell(0, 5, _safe(f"Published: {pub}  |  Affected versions: {aff}"), ln=True)

        # References (max 3)
        if v.references:
            self.set_font("Helvetica", "", 7)
            self.set_text_color(70, 130, 180)
            for ref in v.references[:3]:
                self.cell(0, 4, _safe(f"  > {ref[:100]}"), ln=True)

        self.ln(3)

    def _render_modules_section(self, modules):
        """Render installed modules section"""
        vuln = [m for m in modules if m.has_known_cves]
        safe = [m for m in modules if not m.has_known_cves]

        self._section_title(f"Installed Modules ({len(modules)} detected)")

        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, _safe(
            f"A total of {len(modules)} PrestaShop modules were detected. "
            f"{len(vuln)} module(s) have known CVEs associated with them."
        ))
        self.ln(4)

        # Vulnerable modules
        if vuln:
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(220, 38, 38)
            self.cell(0, 7, "Modules with Known Vulnerabilities", ln=True)
            self.ln(1)

            for m in vuln:
                if self.get_y() > 255:
                    self.add_page()
                ver_str = f" v{m.version}" if m.version else ""
                self.set_font("Helvetica", "B", 9)
                self.set_text_color(220, 38, 38)
                self.cell(0, 5, _safe(f"  {m.name}{ver_str} - {len(m.cve_ids)} CVE(s)"), ln=True)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(80, 80, 80)
                for cve_id in m.cve_ids[:5]:
                    self.cell(0, 4, _safe(f"    > {cve_id}"), ln=True)
                self.ln(1)

            self.ln(3)

        # Safe modules
        if safe:
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(22, 163, 74)
            self.cell(0, 7, f"Clean Modules ({len(safe)})", ln=True)
            self.ln(1)

            self.set_font("Helvetica", "", 8)
            self.set_text_color(80, 80, 80)
            line = ""
            for i, m in enumerate(safe):
                ver_str = f" v{m.version}" if m.version else ""
                entry = f"{m.name}{ver_str}"
                if line:
                    line += ",  "
                line += entry
                # Wrap every ~3 modules per line
                if (i + 1) % 3 == 0:
                    self.cell(0, 4, _safe(f"  {line}"), ln=True)
                    line = ""
            if line:
                self.cell(0, 4, _safe(f"  {line}"), ln=True)

        self.ln(4)

    def _render_security_section(self, sec):
        """Render security assessment section"""
        self._section_title(f"Security Assessment - Risk Grade: {sec.risk_score} ({sec.risk_points}/100)")

        # Risk summary
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        if sec.risk_points >= 75:
            self.multi_cell(0, 5, f"The overall security posture is {'excellent' if sec.risk_points >= 90 else 'good'}. Minor improvements are recommended below.")
        elif sec.risk_points >= 50:
            self.multi_cell(0, 5, "Several security issues need attention. Review the findings below and address them by priority.")
        else:
            self.multi_cell(0, 5, "Critical security issues were detected. Immediate action is strongly recommended.")
        self.ln(4)

        # Score breakdown
        if sec.risk_details:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(80, 80, 80)
            self.cell(0, 6, "Score Breakdown:", ln=True)
            self.set_font("Helvetica", "", 9)
            for detail in sec.risk_details:
                self.cell(0, 5, _safe(f"  - {detail}"), ln=True)
            self.ln(4)

        # HTTP Headers
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(60, 60, 60)
        self.cell(0, 7, "HTTP Security Headers", ln=True)
        self.ln(1)

        for h in sec.headers:
            if self.get_y() > 260:
                self.add_page()
            status = "PASS" if h.severity == "good" else "FAIL"
            color = (22, 163, 74) if h.severity == "good" else (220, 38, 38) if h.severity == "critical" else (202, 138, 4)
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*color)
            self.cell(14, 5, f"[{status}]")
            self.set_text_color(50, 50, 50)
            self.set_font("Helvetica", "", 9)
            self.cell(0, 5, _safe(f"{h.name}: {h.recommendation[:90]}"), ln=True)

        self.ln(4)

        # SSL/TLS
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(60, 60, 60)
        self.cell(0, 7, "SSL/TLS Certificate", ln=True)
        self.ln(1)

        if sec.ssl_info:
            s = sec.ssl_info
            color = (22, 163, 74) if s.severity == "good" else (220, 38, 38)
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*color)
            self.cell(0, 5, _safe(f"  Status: {s.details}"), ln=True)
            self.set_text_color(80, 80, 80)
            self.cell(0, 5, _safe(f"  Protocol: {s.protocol}  |  Issuer: {s.issuer}  |  Days remaining: {s.days_remaining}"), ln=True)
        else:
            self.set_font("Helvetica", "", 9)
            self.set_text_color(150, 150, 150)
            self.cell(0, 5, "  SSL/TLS check could not be performed.", ln=True)

        self.ln(4)

        # Admin Panel
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(60, 60, 60)
        self.cell(0, 7, "Admin Panel Exposure", ln=True)
        self.ln(1)

        a = sec.admin_panel
        color = (220, 38, 38) if a.exposed else (22, 163, 74)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*color)
        self.multi_cell(0, 5, _safe(f"  {a.details}"))
        self.ln(2)


def generate_pdf(result) -> bytes:
    """Generate a professional PDF report"""
    pdf = VulnReportPDF(result)
    return pdf.build()


# ── JSON Export ───────────────────────────────────────────────────────

def generate_json(result) -> str:
    """Generate JSON export with credits"""
    export_data = {
        "report": {
            "tool": "PyPrestaSec — PrestaShop Vulnerability Scanner",
            "generated": datetime.now().isoformat(),
            "created_by": "Andrea Piani",
            "website": "www.andreapiani.com",
            "contact": "andreapiani.dev@gmail.com",
        },
        "scan": {
            "url": result.url,
            "scan_date": result.scan_date.isoformat(),
            "detected_version": {
                "version": result.detected_version.version,
                "source": result.detected_version.source,
                "confidence": result.detected_version.confidence,
            } if result.detected_version else None,
        },
        "summary": {
            "total": result.total_cves,
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
        },
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "description": v.description,
                "published_date": v.published_date,
                "affected_versions": v.affected_versions,
                "references": v.references,
            }
            for v in result.vulnerabilities
        ],
    }

    # Add detected modules
    if result.detected_modules:
        export_data["installed_modules"] = [
            {
                "name": m.name,
                "version": m.version,
                "source": m.source,
                "path": m.path,
                "has_known_cves": m.has_known_cves,
                "cve_ids": m.cve_ids,
            }
            for m in result.detected_modules
        ]

    # Add security assessment if available
    if result.security_report:
        sec = result.security_report
        export_data["security_assessment"] = {
            "risk_grade": sec.risk_score,
            "risk_points": sec.risk_points,
            "risk_details": sec.risk_details,
            "headers": [
                {"name": h.name, "present": h.present, "severity": h.severity, "recommendation": h.recommendation}
                for h in sec.headers
            ],
            "ssl": {
                "valid": sec.ssl_info.valid,
                "protocol": sec.ssl_info.protocol,
                "issuer": sec.ssl_info.issuer,
                "days_remaining": sec.ssl_info.days_remaining,
                "details": sec.ssl_info.details,
            } if sec.ssl_info else None,
            "admin_panel": {
                "exposed": sec.admin_panel.exposed,
                "url_found": sec.admin_panel.url_found,
                "details": sec.admin_panel.details,
            },
        }

    return json.dumps(export_data, indent=2, ensure_ascii=False)


# ── CSV Export ────────────────────────────────────────────────────────

def generate_csv(result) -> str:
    """Generate CSV export with credits header"""
    buf = io.StringIO()
    w = csv.writer(buf)

    # Credits header rows
    w.writerow(["# PyPrestaSec — PrestaShop Vulnerability Report"])
    w.writerow([f"# Target: {result.url}"])
    ver = result.detected_version
    w.writerow([f"# PrestaShop Version: {ver.version if ver else 'Not detected'}"])
    w.writerow([f"# Scan Date: {result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}"])
    w.writerow([f"# Total: {result.total_cves} | Critical: {result.critical_count} | High: {result.high_count} | Medium: {result.medium_count} | Low: {result.low_count}"])
    w.writerow([f"# {CREDITS_LINE}"])
    w.writerow([])

    # Data
    w.writerow(["CVE ID", "Severity", "CVSS Score", "Published", "Affected Versions", "Description", "References"])
    for v in result.vulnerabilities:
        w.writerow([
            v.cve_id,
            v.severity,
            v.cvss_score or "",
            v.published_date[:10] if v.published_date else "",
            "; ".join(v.affected_versions[:5]),
            v.description[:500],
            "; ".join(v.references[:3]),
        ])

    # Installed modules section
    if result.detected_modules:
        w.writerow([])
        vuln_mods = [m for m in result.detected_modules if m.has_known_cves]
        w.writerow([f"# Installed Modules: {len(result.detected_modules)} total, {len(vuln_mods)} with known CVEs"])
        w.writerow(["Module", "Version", "Source", "Has CVEs", "CVE IDs"])
        for m in result.detected_modules:
            w.writerow([
                m.name,
                m.version or "",
                m.source,
                "YES" if m.has_known_cves else "no",
                "; ".join(m.cve_ids[:5]),
            ])

    # Security assessment section
    if result.security_report:
        sec = result.security_report
        w.writerow([])
        w.writerow([f"# Security Assessment: Risk Grade {sec.risk_score} ({sec.risk_points}/100)"])
        w.writerow(["Check", "Status", "Severity", "Details"])
        for h in sec.headers:
            w.writerow([h.name, "Present" if h.present else "Missing", h.severity, h.recommendation[:200]])
        if sec.ssl_info:
            w.writerow(["SSL/TLS", "Valid" if sec.ssl_info.valid else "Invalid", sec.ssl_info.severity, sec.ssl_info.details])
        w.writerow(["Admin Panel", "Exposed" if sec.admin_panel.exposed else "Hidden", sec.admin_panel.severity, sec.admin_panel.details[:200]])

    w.writerow([])
    w.writerow([f"# {CREDITS_LINE}"])

    return buf.getvalue()
