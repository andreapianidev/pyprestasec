import streamlit as st
import sys
import os
import signal
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import PrestaShopScanner
from src.report import generate_pdf, generate_json, generate_csv, CREDITS_LINE
from src.security_checks import SecurityReport
from src.config import (
    APP_TITLE,
    APP_ICON,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    NVD_API_KEY,
)

# ─── Page Config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="PyPrestaSec",
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Header */
    .ps-header { display:flex; align-items:center; gap:1rem; margin-bottom:.5rem; }
    .ps-header h1 { font-size:2.4rem; color:#DF0067; margin:0; }
    .ps-sub { color:#888; font-size:1rem; margin-bottom:1.5rem; }

    /* Severity badges */
    .sev-box {
        padding:.8rem .5rem; border-radius:.6rem; text-align:center;
        color:#fff; font-weight:600;
    }
    .sev-box .num { font-size:2rem; line-height:1.2; }
    .sev-box .lbl { font-size:.75rem; letter-spacing:.05em; }
    .sev-critical { background:#dc2626; }
    .sev-high     { background:#ea580c; }
    .sev-medium   { background:#ca8a04; color:#000; }
    .sev-low      { background:#16a34a; }
    .sev-total    { background:linear-gradient(135deg,#667eea,#764ba2); }

    /* Version card */
    .ver-card {
        background:linear-gradient(135deg,#1e1b4b,#312e81);
        border:1px solid #4338ca; border-radius:.7rem;
        padding:1.2rem; color:#e0e7ff;
    }
    .ver-card .ver-num { font-size:2rem; font-weight:700; color:#a5b4fc; }
    .ver-card .ver-src { font-size:.8rem; color:#818cf8; margin-top:.3rem; }

    /* Log console */
    .log-container {
        background:#0d1117; border:1px solid #30363d; border-radius:.5rem;
        padding:.8rem; font-family:'JetBrains Mono','Fira Code',monospace;
        font-size:.78rem; line-height:1.6; max-height:320px; overflow-y:auto;
        color:#c9d1d9;
    }
    .log-info    { color:#58a6ff; }
    .log-success { color:#3fb950; }
    .log-warning { color:#d29922; }
    .log-error   { color:#f85149; }
    .log-debug   { color:#8b949e; }

    /* Kill button */
    .kill-btn button {
        background:#dc2626 !important; color:#fff !important;
        border:none !important; font-weight:600 !important;
    }
    .kill-btn button:hover { background:#b91c1c !important; }

    /* Hide default metric label overflow */
    div[data-testid="stMetricValue"] { font-size:1rem; }

    /* Risk score badge */
    .risk-badge {
        display:inline-flex; align-items:center; justify-content:center;
        width:5rem; height:5rem; border-radius:50%; font-size:2.5rem;
        font-weight:800; color:#fff; margin:auto;
    }
    .risk-A { background:#16a34a; }
    .risk-B { background:#65a30d; }
    .risk-C { background:#ca8a04; }
    .risk-D { background:#ea580c; }
    .risk-F { background:#dc2626; }

    /* Security check rows */
    .sec-row { display:flex; align-items:center; gap:.5rem; padding:.35rem 0; font-size:.85rem; }
    .sec-good    { color:#3fb950; }
    .sec-warning { color:#d29922; }
    .sec-critical{ color:#f85149; }
</style>
""", unsafe_allow_html=True)


# ─── Session State ────────────────────────────────────────────────────
def init_state():
    defaults = {
        "scan_result": None,
        "is_scanning": False,
        "api_key": NVD_API_KEY,
        "logs": [],
        "scan_url": "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ─── Logging helper ──────────────────────────────────────────────────
def add_log(level: str, message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append({"ts": ts, "level": level, "msg": message})


def render_logs():
    if not st.session_state.logs:
        return
    lines = []
    for entry in st.session_state.logs:
        css = f"log-{entry['level']}"
        esc = entry["msg"].replace("<", "&lt;").replace(">", "&gt;")
        lines.append(f'<span class="{css}">[{entry["ts"]}] {esc}</span>')
    html = "<br>".join(lines)
    st.markdown(f'<div class="log-container">{html}</div>', unsafe_allow_html=True)


# ─── Header ──────────────────────────────────────────────────────────
def render_header():
    st.markdown(
        f'<div class="ps-header">'
        f'<span style="font-size:3rem">{APP_ICON}</span>'
        f'<h1>PyPrestaSec</h1>'
        f'</div>'
        f'<div class="ps-sub">PrestaShop Vulnerability Scanner &mdash; powered by NVD CVE Database</div>',
        unsafe_allow_html=True,
    )


# ─── Sidebar ─────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.header("⚙️ Settings")

        api_key = st.text_input(
            "NVD API Key",
            value=st.session_state.api_key,
            type="password",
            help="Paste your free NVD API key here for faster scans.",
        )
        st.session_state.api_key = api_key
        st.markdown(
            '🔑 <a href="https://nvd.nist.gov/developers/request-an-api-key" '
            'target="_blank" style="color:#818cf8; font-size:.85rem;">'
            'Get your FREE NVD API key here</a>',
            unsafe_allow_html=True,
        )

        st.divider()
        st.subheader("Scan Options")

        check_all = st.checkbox("Fetch ALL PrestaShop CVEs", value=True,
                                help="Slower but more thorough")
        max_results = st.slider("Max CVE results", 20, 300, 100, 20)
        run_security = st.checkbox("Run security checks", value=True,
                                   help="HTTP headers, SSL/TLS, admin panel detection")

        st.divider()
        st.subheader("Manual Version (optional)")
        manual_ver = st.text_input(
            "PrestaShop version",
            placeholder="e.g. 1.6.1.24 or 1.7.8.7",
            help="If auto-detection fails, enter the version manually here",
        )

        st.divider()

        # ── Kill button ──
        st.markdown('<div class="kill-btn">', unsafe_allow_html=True)
        if st.button("🛑 Stop Server & Quit", use_container_width=True):
            st.warning("Shutting down...")
            os.kill(os.getpid(), signal.SIGTERM)
        st.markdown('</div>', unsafe_allow_html=True)

        st.divider()
        st.markdown(
            '<div style="text-align:center; font-size:.75rem; color:#666;">'
            'Open-source &bull; MIT License<br>'
            '<a href="https://github.com/andreapianidev/PyPrestaSec" target="_blank" style="color:#818cf8;">GitHub</a> &bull; '
            '<a href="https://www.andreapiani.com" target="_blank" style="color:#818cf8;">andreapiani.com</a>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "Data: [NVD](https://nvd.nist.gov/) &bull; "
            "[PrestaShop Advisories](https://build.prestashop-project.org/news/tags/security/)\n\n"
            "⚠️ For authorized security research only."
        )

        return {
            "api_key": api_key,
            "check_all": check_all,
            "max_results": max_results,
            "manual_version": manual_ver,
            "run_security": run_security,
        }


# ─── Scan Form ────────────────────────────────────────────────────────
def render_scan_form():
    col1, col2 = st.columns([4, 1])
    with col1:
        url = st.text_input(
            "🎯 Target URL",
            placeholder="https://www.example-shop.com",
            label_visibility="collapsed",
        )
    with col2:
        scan = st.button("🔍 Scan", type="primary", use_container_width=True,
                         disabled=st.session_state.is_scanning)
    return url, scan


# ─── Perform Scan ─────────────────────────────────────────────────────
def perform_scan(url: str, config: dict):
    if not url:
        st.error("Enter a URL to scan")
        return

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    st.session_state.logs = []
    st.session_state.scan_result = None
    st.session_state.is_scanning = True
    st.session_state.scan_url = url

    # Use st.status for real-time visual feedback
    with st.status("🔍 **Scanning in progress...**", expanded=True) as status:
        log_placeholder = st.empty()

        def live_log(level: str, message: str):
            """Log callback that updates UI in real-time"""
            add_log(level, message)
            # Re-render log console inside the status container
            lines = []
            for entry in st.session_state.logs[-20:]:  # last 20 lines
                css = f"log-{entry['level']}"
                esc = entry["msg"].replace("<", "&lt;").replace(">", "&gt;")
                lines.append(f'<span class="{css}">[{entry["ts"]}] {esc}</span>')
            html = "<br>".join(lines)
            log_placeholder.markdown(f'<div class="log-container">{html}</div>', unsafe_allow_html=True)

        live_log("info", f"Target: {url}")
        if config["api_key"]:
            live_log("info", "NVD API key configured (higher rate limit)")
        else:
            live_log("warning", "No API key - using public rate limit (slower)")

        try:
            scanner = PrestaShopScanner(
                api_key=config["api_key"],
                log_callback=live_log,
            )
            result = scanner.scan(
                url,
                check_all_cves=config["check_all"],
                manual_version=config["manual_version"],
                max_results=config["max_results"],
            )
            st.session_state.scan_result = result
            live_log("success", "SCAN COMPLETE")
            status.update(label="✅ **Scan complete!**", state="complete", expanded=False)
        except Exception as e:
            live_log("error", f"Scan failed: {e}")
            status.update(label="❌ **Scan failed**", state="error", expanded=True)
        finally:
            st.session_state.is_scanning = False


# ─── Version Card ─────────────────────────────────────────────────────
def render_version_card(result):
    v = result.detected_version
    if v:
        ver_html = f"""
        <div class="ver-card">
            <div style="display:flex;align-items:baseline;gap:.6rem;">
                <span style="font-size:1rem;">📦 PrestaShop</span>
                <span class="ver-num">{v.version}</span>
            </div>
            <div class="ver-src">Detected via: {v.source} &bull; Confidence: {v.confidence}</div>
        </div>"""
    else:
        ver_html = """
        <div class="ver-card" style="border-color:#dc2626;">
            <span style="font-size:1rem;">📦 PrestaShop</span>
            <span class="ver-num" style="color:#f87171;">Not detected</span>
            <div class="ver-src" style="color:#fca5a5;">
                Tip: enter the version manually in the sidebar, or the scan will show ALL known CVEs
            </div>
        </div>"""
    st.markdown(ver_html, unsafe_allow_html=True)


# ─── Summary ──────────────────────────────────────────────────────────
def render_summary(result):
    st.markdown("---")
    st.subheader("📊 Scan Results")

    col_v, col_u, col_d = st.columns([2, 2, 1])
    with col_v:
        render_version_card(result)
    with col_u:
        st.markdown(f"**🌐 Target:** `{result.url}`")
    with col_d:
        st.markdown(f"**🕐 Date:** `{result.scan_date.strftime('%Y-%m-%d %H:%M')}`")

    st.write("")

    # Severity boxes
    cols = st.columns(5)
    data = [
        ("CRITICAL", result.critical_count, "sev-critical"),
        ("HIGH", result.high_count, "sev-high"),
        ("MEDIUM", result.medium_count, "sev-medium"),
        ("LOW", result.low_count, "sev-low"),
        ("TOTAL", result.total_cves, "sev-total"),
    ]
    for col, (label, count, cls) in zip(cols, data):
        with col:
            st.markdown(
                f'<div class="sev-box {cls}">'
                f'<div class="num">{count}</div>'
                f'<div class="lbl">{label}</div></div>',
                unsafe_allow_html=True,
            )


# ─── Vulnerability List ──────────────────────────────────────────────
def render_vulns(result):
    st.markdown("---")
    st.subheader("📋 Vulnerabilities")

    if not result.vulnerabilities:
        st.success("No known vulnerabilities found!")
        return

    col1, col2 = st.columns([1, 3])
    with col1:
        sev_filter = st.multiselect(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        )
    with col2:
        search = st.text_input("Search", placeholder="CVE ID or keyword...")

    vulns = [v for v in result.vulnerabilities if v.severity in sev_filter]
    if search:
        s = search.lower()
        vulns = [v for v in vulns if s in v.cve_id.lower() or s in v.description.lower()]

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda x: (order.get(x.severity, 5), -(x.cvss_score or 0)))

    st.caption(f"Showing **{len(vulns)}** of {len(result.vulnerabilities)}")

    for vuln in vulns:
        icon = SEVERITY_ICONS.get(vuln.severity, "⚪")
        score_str = f"{vuln.cvss_score}" if vuln.cvss_score else "N/A"

        with st.expander(f"{icon} **{vuln.cve_id}** — {vuln.severity} (CVSS {score_str})"):
            st.markdown(vuln.description)

            c1, c2, c3 = st.columns(3)
            with c1:
                color = SEVERITY_COLORS.get(vuln.severity, "#999")
                st.markdown(f"**Severity:** <span style='color:{color};font-weight:700'>{vuln.severity}</span>", unsafe_allow_html=True)
                st.markdown(f"**CVSS:** `{score_str}`")
            with c2:
                st.markdown(f"**Published:** {vuln.published_date[:10] if vuln.published_date else 'N/A'}")
                st.markdown(f"**Modified:** {vuln.modified_date[:10] if vuln.modified_date else 'N/A'}")
            with c3:
                if vuln.affected_versions:
                    st.markdown(f"**Affected:** {', '.join(vuln.affected_versions[:5])}")

            if vuln.references:
                st.markdown("**References:**")
                for ref in vuln.references[:5]:
                    short = ref[:90] + "..." if len(ref) > 90 else ref
                    st.markdown(f"- [{short}]({ref})")


# ─── Installed Modules ────────────────────────────────────────────────
def render_modules(modules):
    st.markdown("---")
    st.subheader("🧩 Installed Modules")

    if not modules:
        st.info("No modules detected. The site may block directory probing or use non-standard paths.")
        return

    vuln_modules = [m for m in modules if m.has_known_cves]
    safe_modules = [m for m in modules if not m.has_known_cves]

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Modules", len(modules))
    with col2:
        st.metric("With Known CVEs", len(vuln_modules), delta=None if len(vuln_modules) == 0 else f"-{len(vuln_modules)}", delta_color="inverse")
    with col3:
        st.metric("Clean", len(safe_modules))

    # Vulnerable modules first
    if vuln_modules:
        st.markdown("#### ⚠️ Modules with Known Vulnerabilities")
        for mod in vuln_modules:
            ver_str = f" `v{mod.version}`" if mod.version else ""
            with st.expander(f"❌ **{mod.name}**{ver_str} — {len(mod.cve_ids)} CVE(s)", expanded=True):
                st.markdown(f"**Source:** {mod.source}")
                if mod.path:
                    st.markdown(f"**Path:** `{mod.path}`")
                st.markdown("**Related CVEs:**")
                for cve_id in mod.cve_ids[:10]:
                    st.markdown(f"- [`{cve_id}`](https://nvd.nist.gov/vuln/detail/{cve_id})")

    # Safe modules
    if safe_modules:
        with st.expander(f"✅ Clean Modules ({len(safe_modules)})", expanded=False):
            cols_per_row = 3
            rows = [safe_modules[i:i+cols_per_row] for i in range(0, len(safe_modules), cols_per_row)]
            for row in rows:
                cols = st.columns(cols_per_row)
                for col, mod in zip(cols, row):
                    with col:
                        ver_str = f" v{mod.version}" if mod.version else ""
                        st.markdown(
                            f'<div style="background:#1a1a2e; border:1px solid #30363d; border-radius:.4rem; '
                            f'padding:.5rem .7rem; margin-bottom:.3rem; font-size:.82rem;">'
                            f'📦 <b>{mod.name}</b>{ver_str}'
                            f'<br><span style="color:#666; font-size:.7rem;">{mod.source}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )


# ─── Security Checks ─────────────────────────────────────────────────
def render_security_checks(sec: SecurityReport):
    st.markdown("---")
    st.subheader("🔒 Security Assessment")

    # Risk score + summary
    col_score, col_details = st.columns([1, 4])

    with col_score:
        grade = sec.risk_score
        st.markdown(
            f'<div style="text-align:center;">'
            f'<div class="risk-badge risk-{grade}">{grade}</div>'
            f'<div style="color:#888; font-size:.8rem; margin-top:.4rem;">Score: {sec.risk_points}/100</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with col_details:
        if sec.risk_points >= 75:
            st.success(f"**Risk Grade: {grade}** — Security posture is {'excellent' if sec.risk_points >= 90 else 'good'}.")
        elif sec.risk_points >= 50:
            st.warning(f"**Risk Grade: {grade}** — Several security issues need attention.")
        else:
            st.error(f"**Risk Grade: {grade}** — Critical security issues detected. Immediate action recommended.")

        if sec.risk_details:
            with st.expander("Score breakdown"):
                for detail in sec.risk_details:
                    st.markdown(f"- {detail}")

    # Tabs for each check category
    tab_hdrs, tab_ssl, tab_admin = st.tabs(["🌐 HTTP Headers", "🔐 SSL/TLS", "🚪 Admin Panel"])

    # ── Headers tab ──
    with tab_hdrs:
        for h in sec.headers:
            icon_map = {"good": "✅", "warning": "⚠️", "critical": "❌"}
            icon = icon_map.get(h.severity, "❓")
            css = f"sec-{h.severity}"

            if h.present and "info leak" not in h.name.lower():
                st.markdown(
                    f'<div class="sec-row {css}">{icon} <b>{h.name}</b>: '
                    f'<code>{(h.value or "")[:80]}</code></div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="sec-row {css}">{icon} <b>{h.name}</b> — {h.recommendation}</div>',
                    unsafe_allow_html=True,
                )

    # ── SSL tab ──
    with tab_ssl:
        ssl = sec.ssl_info
        if ssl:
            icon = {"good": "✅", "warning": "⚠️", "critical": "❌"}.get(ssl.severity, "❓")
            st.markdown(f"{icon} **{ssl.details}**")
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f"**Valid:** {'Yes' if ssl.valid else 'No'}")
                st.markdown(f"**Protocol:** `{ssl.protocol}`")
            with c2:
                st.markdown(f"**Issuer:** {ssl.issuer}")
                st.markdown(f"**Subject:** {ssl.subject}")
            with c3:
                st.markdown(f"**Expires:** {ssl.expires}")
                st.markdown(f"**Days left:** {ssl.days_remaining}")
        else:
            st.warning("SSL/TLS check could not be performed.")

    # ── Admin panel tab ──
    with tab_admin:
        admin = sec.admin_panel
        if admin.exposed:
            st.error(f"❌ **Admin panel exposed!**\n\n{admin.details}")
            st.markdown(f"Found at: `{admin.url_found}`")
        else:
            st.success(f"✅ **{admin.details}**")


def render_export(result):
    st.markdown("---")
    st.subheader("💾 Export Report")
    st.caption("Download the full vulnerability report to share with your client.")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Generate PDF lazily and cache in session state
    if "pdf_cache" not in st.session_state or st.session_state.get("pdf_cache_url") != result.url:
        try:
            st.session_state.pdf_cache = generate_pdf(result)
            st.session_state.pdf_cache_url = result.url
        except Exception as e:
            st.session_state.pdf_cache = None
            st.error(f"PDF generation error: {e}")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        if st.session_state.get("pdf_cache"):
            st.download_button(
                "📄 PDF Report",
                st.session_state.pdf_cache,
                f"prestasec_report_{ts}.pdf",
                "application/pdf",
                use_container_width=True,
            )
        else:
            st.button("📄 PDF (error)", disabled=True, use_container_width=True)

    with c2:
        st.download_button(
            "📥 JSON",
            generate_json(result),
            f"prestasec_{ts}.json",
            "application/json",
            use_container_width=True,
        )

    with c3:
        st.download_button(
            "📥 CSV",
            generate_csv(result),
            f"prestasec_{ts}.csv",
            "text/csv",
            use_container_width=True,
        )

    with c4:
        if st.button("🗑️ Clear Results", use_container_width=True):
            st.session_state.scan_result = None
            st.session_state.logs = []
            st.session_state.pdf_cache = None
            st.rerun()


# ─── Credits Footer ──────────────────────────────────────────────────
def render_credits():
    st.markdown("---")
    st.markdown(
        '<div style="text-align:center; padding:1.5rem 0 .5rem 0;">'
        '<span style="color:#DF0067; font-weight:700; font-size:.95rem;">PyPrestaSec</span>'
        '<br>'
        '<span style="color:#888; font-size:.8rem;">'
        'Created by <b>Andrea Piani</b> &mdash; '
        '<a href="https://www.andreapiani.com" target="_blank" style="color:#818cf8;">www.andreapiani.com</a> &mdash; '
        '<a href="mailto:andreapiani.dev@gmail.com" style="color:#818cf8;">andreapiani.dev@gmail.com</a>'
        '</span></div>',
        unsafe_allow_html=True,
    )


# ─── Main ─────────────────────────────────────────────────────────────
def main():
    init_state()
    render_header()
    config = render_sidebar()

    url, scan_clicked = render_scan_form()

    if scan_clicked:
        perform_scan(url, config)

    # Live log console (always visible when there are logs)
    if st.session_state.logs:
        with st.expander("📟 Scan Log", expanded=st.session_state.is_scanning or not st.session_state.scan_result):
            render_logs()

    # Results
    if st.session_state.scan_result:
        render_summary(st.session_state.scan_result)
        if st.session_state.scan_result.detected_modules is not None:
            render_modules(st.session_state.scan_result.detected_modules)
        if st.session_state.scan_result.security_report:
            render_security_checks(st.session_state.scan_result.security_report)
        render_vulns(st.session_state.scan_result)
        render_export(st.session_state.scan_result)
        render_credits()


if __name__ == "__main__":
    main()
