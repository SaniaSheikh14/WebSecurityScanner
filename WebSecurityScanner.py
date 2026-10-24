import csv
import io
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import streamlit as st

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebSec Audit Tool",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Base */
    [data-testid="stAppViewContainer"] {
        background-color: #0d1117;
        color: #e6edf3;
    }
    [data-testid="stSidebar"] { background-color: #161b22; }
    h1, h2, h3, h4, label, p { color: #e6edf3 !important; }

    /* Metric cards */
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px 24px;
        text-align: center;
    }
    .metric-label {
        font-size: 12px;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 36px;
        font-weight: 700;
        color: #58a6ff;
    }
    .metric-value.grade-a  { color: #3fb950; }
    .metric-value.grade-b  { color: #58a6ff; }
    .metric-value.grade-c  { color: #d29922; }
    .metric-value.grade-f  { color: #f85149; }
    .metric-value.risk     { color: #f85149; }
    .metric-value.protocol { color: #58a6ff; }

    /* Input + button row */
    div[data-testid="stTextInput"] input {
        background-color: #161b22 !important;
        border: 1px solid #30363d !important;
        color: #e6edf3 !important;
        border-radius: 6px;
    }
    div[data-testid="stButton"] > button {
        background-color: #238636;
        color: #ffffff;
        border: 1px solid #2ea043;
        border-radius: 6px;
        font-weight: 600;
        padding: 0.45rem 1.4rem;
    }
    div[data-testid="stButton"] > button:hover {
        background-color: #2ea043;
        border-color: #3fb950;
    }

    /* Results table */
    .header-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 18px;
        margin-bottom: 8px;
    }
    .header-name { font-weight: 600; font-size: 14px; color: #e6edf3; }
    .header-desc { font-size: 12px; color: #8b949e; margin-top: 2px; }
    .badge {
        font-size: 11px;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 20px;
    }
    .badge-present { background-color: #1f3a2a; color: #3fb950; border: 1px solid #2ea043; }
    .badge-missing  { background-color: #3d1a1a; color: #f85149; border: 1px solid #da3633; }
    .badge-warn     { background-color: #3d2d00; color: #d29922; border: 1px solid #9e6a03; }

    /* Section divider */
    hr { border-color: #30363d; }
</style>
""", unsafe_allow_html=True)

# ── Constants ──────────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Enforces HTTPS connections (HSTS)",
        "critical": True,
    },
    "Content-Security-Policy": {
        "desc": "Restricts sources of executable scripts",
        "critical": True,
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing",
        "critical": False,
    },
    "X-Frame-Options": {
        "desc": "Protects against clickjacking attacks",
        "critical": False,
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information in requests",
        "critical": False,
    },
    "Permissions-Policy": {
        "desc": "Limits access to browser APIs / features",
        "critical": False,
    },
}

CORS_HEADER = "Access-Control-Allow-Origin"

# ── Remediation directives (per missing header) ────────────────────────────────
REMEDIATION_DIRECTIVES = {
    "Strict-Transport-Security": {
        "nginx":  'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    },
    "Content-Security-Policy": {
        "nginx":  "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;",
        "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"",
    },
    "X-Content-Type-Options": {
        "nginx":  'add_header X-Content-Type-Options "nosniff" always;',
        "apache": 'Header always set X-Content-Type-Options "nosniff"',
    },
    "X-Frame-Options": {
        "nginx":  'add_header X-Frame-Options "SAMEORIGIN" always;',
        "apache": 'Header always set X-Frame-Options "SAMEORIGIN"',
    },
    "Referrer-Policy": {
        "nginx":  'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    },
    "Permissions-Policy": {
        "nginx":  'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
    },
    "Access-Control-Allow-Origin": {
        "nginx":  'add_header Access-Control-Allow-Origin "https://yourdomain.com" always;',
        "apache": 'Header always set Access-Control-Allow-Origin "https://yourdomain.com"',
    },
}

# ── Helpers ────────────────────────────────────────────────────────────────────
def compute_grade(present: int, total: int, critical_risks: int) -> str:
    ratio = present / total if total else 0
    if critical_risks >= 2:
        return "F"
    if ratio >= 0.9:
        return "A"
    if ratio >= 0.7:
        return "B"
    if ratio >= 0.4:
        return "C"
    return "F"


def grade_css_class(grade: str) -> str:
    return {"A": "grade-a", "B": "grade-b", "C": "grade-c", "F": "grade-f"}.get(grade, "")


def audit_url(url: str) -> dict:
    """Fetch headers from *url* and return an audit result dict."""
    parsed = urlparse(url)
    protocol = parsed.scheme.upper() if parsed.scheme else "UNKNOWN"

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except requests.exceptions.RequestException as exc:
        return {"error": str(exc)}

    results = {}
    critical_risks = 0
    for name, meta in SECURITY_HEADERS.items():
        present = name.lower() in headers
        value = headers.get(name.lower(), "")
        if not present and meta["critical"]:
            critical_risks += 1
        results[name] = {"present": present, "value": value, **meta}

    # CORS check
    cors_value = headers.get(CORS_HEADER.lower(), "")
    cors_wildcard = cors_value.strip() == "*"
    if cors_wildcard:
        critical_risks += 1

    implemented = sum(1 for v in results.values() if v["present"])
    grade = compute_grade(implemented, len(SECURITY_HEADERS), critical_risks)

    return {
        "error": None,
        "protocol": protocol,
        "status_code": resp.status_code,
        "headers": results,
        "cors_value": cors_value,
        "cors_wildcard": cors_wildcard,
        "implemented": implemented,
        "total": len(SECURITY_HEADERS),
        "critical_risks": critical_risks,
        "grade": grade,
    }

def build_json_report(url: str, result: dict) -> str:
    """Serialise scan result to a pretty-printed JSON string."""
    rows = []
    for name, meta in result["headers"].items():
        rows.append({
            "header":   name,
            "status":   "present" if meta["present"] else "missing",
            "critical": meta["critical"],
            "value":    meta["value"],
        })
    cors_status = (
        "wildcard" if result["cors_wildcard"]
        else ("not_set" if not result["cors_value"] else "restricted")
    )
    rows.append({
        "header":   CORS_HEADER,
        "status":   cors_status,
        "critical": result["cors_wildcard"],
        "value":    result["cors_value"],
    })
    payload = {
        "scanned_url":    url,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "grade":          result["grade"],
        "implemented":    result["implemented"],
        "total":          result["total"],
        "critical_risks": result["critical_risks"],
        "protocol":       result["protocol"],
        "status_code":    result["status_code"],
        "headers":        rows,
    }
    return json.dumps(payload, indent=2)


def build_csv_report(url: str, result: dict) -> str:
    """Serialise scan result to a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["scanned_url", url])
    writer.writerow(["timestamp", datetime.now(timezone.utc).isoformat()])
    writer.writerow(["grade", result["grade"]])
    writer.writerow(["implemented", result["implemented"]])
    writer.writerow(["total", result["total"]])
    writer.writerow(["critical_risks", result["critical_risks"]])
    writer.writerow(["protocol", result["protocol"]])
    writer.writerow(["status_code", result["status_code"]])
    writer.writerow([])
    writer.writerow(["header", "status", "critical", "value"])
    for name, meta in result["headers"].items():
        writer.writerow([
            name,
            "present" if meta["present"] else "missing",
            meta["critical"],
            meta["value"],
        ])
    cors_status = (
        "wildcard" if result["cors_wildcard"]
        else ("not_set" if not result["cors_value"] else "restricted")
    )
    writer.writerow([CORS_HEADER, cors_status, result["cors_wildcard"], result["cors_value"]])
    return output.getvalue()


# ── UI ─────────────────────────────────────────────────────────────────────────
st.title("🛡️ Automated Web Security & Header Scanner")
st.markdown(
    "<p style='color:#8b949e; font-size:15px; margin-top:-10px;'>"
    "Audits domains for defensive HTTP security headers and CORS misconfigurations "
    "— giving you an instant security posture grade."
    "</p>",
    unsafe_allow_html=True,
)
st.markdown("<hr>", unsafe_allow_html=True)

# ── Input row ──────────────────────────────────────────────────────────────────
col_input, col_btn = st.columns([5, 1])
with col_input:
    url = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
    )
with col_btn:
    run = st.button("🔍 Run Security Audit", use_container_width=True)

# ── Metric cards (default / placeholder state) ─────────────────────────────────
grade_ph, headers_ph, risks_ph, proto_ph = st.columns(4)

def metric_card(col, label: str, value: str, css_extra: str = "") -> None:
    col.markdown(
        f"""<div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value {css_extra}">{value}</div>
        </div>""",
        unsafe_allow_html=True,
    )

if not run or not url:
    metric_card(grade_ph,   "Overall Security Grade",  "—")
    metric_card(headers_ph, "Headers Implemented",      "— / 6")
    metric_card(risks_ph,   "Critical Risks Found",     "—")
    metric_card(proto_ph,   "Scanned Protocol",         "—")

# ── Audit execution ────────────────────────────────────────────────────────────
if run and url:
    with st.spinner("Scanning target…"):
        result = audit_url(url)

    if result["error"]:
        st.error(f"❌ Could not reach the target: `{result['error']}`")
        metric_card(grade_ph,   "Overall Security Grade",  "ERR")
        metric_card(headers_ph, "Headers Implemented",      "— / 6")
        metric_card(risks_ph,   "Critical Risks Found",     "—")
        metric_card(proto_ph,   "Scanned Protocol",         "—")
    else:
        grade = result["grade"]
        metric_card(grade_ph,   "Overall Security Grade",
                    grade, grade_css_class(grade))
        metric_card(headers_ph, "Headers Implemented",
                    f"{result['implemented']} / {result['total']}")
        metric_card(risks_ph,   "Critical Risks Found",
                    str(result["critical_risks"]), "risk" if result["critical_risks"] else "grade-a")
        metric_card(proto_ph,   "Scanned Protocol",
                    result["protocol"], "protocol")

        st.markdown("<hr>", unsafe_allow_html=True)
        st.subheader("🔎 Header Analysis")

        for name, meta in result["headers"].items():
            badge_cls  = "badge-present" if meta["present"] else "badge-missing"
            badge_text = "PRESENT" if meta["present"] else "MISSING"
            value_html = (
                f'<div style="font-size:11px;color:#58a6ff;margin-top:4px;">Value: <code>{meta["value"][:80]}</code></div>'
                if meta["present"] else ""
            )
            st.markdown(
                f'<div class="header-row"><div><div class="header-name">{name}</div><div class="header-desc">{meta["desc"]}</div>{value_html}</div><span class="badge {badge_cls}">{badge_text}</span></div>',
                unsafe_allow_html=True,
            )

        st.markdown("<hr>", unsafe_allow_html=True)
        st.subheader("🌐 CORS Configuration")
        if not result["cors_value"]:
            st.markdown(
                '<div class="header-row"><div class="header-name">'
                'Access-Control-Allow-Origin</div>'
                '<span class="badge badge-warn">NOT SET</span></div>',
                unsafe_allow_html=True,
            )
        elif result["cors_wildcard"]:
            st.markdown(
                '<div class="header-row"><div><div class="header-name">'
                'Access-Control-Allow-Origin</div>'
                '<div class="header-desc">⚠️ Wildcard (*) allows any origin — critical misconfiguration</div>'
                '</div><span class="badge badge-missing">WILDCARD</span></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div class="header-row"><div><div class="header-name">'
                f'Access-Control-Allow-Origin</div>'
                f'<div class="header-desc">Value: <code>{result["cors_value"]}</code></div>'
                f'</div><span class="badge badge-present">RESTRICTED</span></div>',
                unsafe_allow_html=True,
            )

        # ── Hardening Recommendations ─────────────────────────────────────────
        missing_headers = [
            name for name, meta in result["headers"].items() if not meta["present"]
        ]
        if result["cors_wildcard"]:
            missing_headers.append(CORS_HEADER)

        if missing_headers:
            st.markdown("<hr>", unsafe_allow_html=True)
            st.subheader("🔧 Hardening Recommendations")
            st.markdown(
                "<p style='color:#8b949e; font-size:13px; margin-top:-8px;'>"
                "Ready-to-copy server directives for every missing or misconfigured header.</p>",
                unsafe_allow_html=True,
            )
            for name in missing_headers:
                directives = REMEDIATION_DIRECTIVES.get(name)
                if not directives:
                    continue
                with st.expander(f"⚠️  {name}", expanded=False):
                    st.markdown("**Nginx** — add inside your `server {}` or `location {}` block:")
                    st.code(directives["nginx"], language="nginx")
                    st.markdown("**Apache** — add inside `<VirtualHost>` or `.htaccess` (requires `mod_headers`):")
                    st.code(directives["apache"], language="apache")

        # ── Export Report ─────────────────────────────────────────────────────
        st.markdown("<hr>", unsafe_allow_html=True)
        st.subheader("📥 Export Report")
        export_col_json, export_col_csv, _ = st.columns([1, 1, 4])

        safe_host = urlparse(url).netloc.replace(".", "_") or "report"
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        with export_col_json:
            st.download_button(
                label="⬇ Download JSON",
                data=build_json_report(url, result),
                file_name=f"websec_{safe_host}_{ts}.json",
                mime="application/json",
                use_container_width=True,
            )
        with export_col_csv:
            st.download_button(
                label="⬇ Download CSV",
                data=build_csv_report(url, result),
                file_name=f"websec_{safe_host}_{ts}.csv",
                mime="text/csv",
                use_container_width=True,
            )
