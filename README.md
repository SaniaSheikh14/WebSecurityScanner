# 🛡️ Automated Web Security Header & CORS Scanner

A lightweight, browser-based security auditing tool built with **Streamlit** that inspects any publicly reachable URL for missing defensive HTTP headers, CORS misconfigurations, and protocol hygiene — and returns an instant security grade, ready-to-copy server hardening directives, and a downloadable audit report.

---

## Overview

Modern web applications depend on a thin layer of HTTP response headers to instruct browsers to enforce security policies: HTTPS-only connections, script-source allowlists, frame-embedding rules, and more. When these headers are absent or misconfigured they become silent attack vectors.

This tool automates that inspection in four steps:

1. Paste a target URL.
2. The scanner fetches the live response headers via a single `requests.get` call.
3. It cross-references them against six critical/important security headers plus the `Access-Control-Allow-Origin` CORS directive.
4. Results appear instantly as colour-coded **PRESENT / MISSING / WILDCARD** badges, a letter grade (**A → F**), per-header Nginx and Apache hardening directives for anything missing, and a one-click downloadable JSON or CSV audit report.

---

## Key Features

| Feature | Detail |
|---|---|
| **Defensive header compliance checks** | Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy` — distinguishing *critical* from *informational* absences |
| **CORS policy inspection** | Detects a missing `Access-Control-Allow-Origin` header (warned), a wildcard `*` value (critical risk), and a properly scoped origin (passes) |
| **Live security scoring** | `compute_grade()` weights critical risks heavily — two or more critical gaps immediately floors the grade to **F** regardless of other headers present |
| **🔧 Hardening Recommendations** | For every missing or misconfigured header, a collapsible expander shows ready-to-copy `add_header` / `Header always set` directives for both Nginx and Apache |
| **📥 JSON & CSV export** | Two `st.download_button` widgets export the full audit table, target URL, UTC timestamp, and final score — filenames are auto-stamped (e.g. `websec_github_com_20250711T143022Z.json`) |
| **GitHub-dark themed UI** | Custom CSS injected via `st.markdown` gives the app a `#0d1117` dark theme with colour-coded metric cards and pill badges |
| **Zero-setup scanning** | `allow_redirects=True` handles redirect chains transparently; protocol is extracted from the resolved URL |
| **Graceful error handling** | Network failures surface as a user-visible error banner; all metric cards degrade to `ERR` / `—` placeholder state |

---

## Project Structure

```
CyberSecurityProject/
├── WebSecurityScanner.py   # Streamlit app — UI, audit logic, remediation, export
├── requirements.txt        # Python dependencies
└── README.md
```

---

## Technologies Used

| Technology | Role |
|---|---|
| **Python 3.9+** | Runtime language |
| **Streamlit ≥ 1.28** | Web UI framework — layout, widgets, download buttons |
| **Requests ≥ 2.31** | HTTP header fetching with redirect support |
| **Pandas ≥ 2.0** | Dependency (available for future tabular analysis) |
| **IBM Bob** | AI pair programmer — UI scaffolding, audit logic, bug fixing, remediation snippets (see dedicated section below) |

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.9 + |
| pip | any recent version |
| Internet access | required to fetch live headers from target URLs |

---

## Installation & Running

### 1 — Clone or download the project

```bash
git clone https://github.com/<your-username>/CyberSecurityProject.git
cd CyberSecurityProject
```

### 2 — (Recommended) Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` pins three packages:

```
streamlit>=1.28.0
requests>=2.31.0
pandas>=2.0.0
```

### 4 — Launch the app

```bash
streamlit run WebSecurityScanner.py
```

Streamlit will print a local URL (typically `http://localhost:8501`). Open it in any browser, paste a target URL, and click **🔍 Run Security Audit**.

---

## How the Grading Works

The overall security grade is computed by `compute_grade()` using two inputs:

- **`ratio`** — fraction of the six audited headers that are present.
- **`critical_risks`** — counter incremented when a critical header (`Strict-Transport-Security`, `Content-Security-Policy`) is missing, **or** a CORS wildcard (`*`) is detected.

| Condition | Grade |
|---|---|
| 2 or more critical risks | **F** |
| ratio ≥ 90 % | **A** |
| ratio ≥ 70 % | **B** |
| ratio ≥ 40 % | **C** |
| ratio < 40 % | **F** |

---

## Audited Security Headers

| Header | Purpose | Critical? |
|---|---|---|
| `Strict-Transport-Security` | Enforces HTTPS (HSTS) | ✅ Yes |
| `Content-Security-Policy` | Restricts sources of executable scripts | ✅ Yes |
| `X-Content-Type-Options` | Prevents MIME-type sniffing | No |
| `X-Frame-Options` | Protects against clickjacking | No |
| `Referrer-Policy` | Controls referrer info in outbound requests | No |
| `Permissions-Policy` | Limits access to browser APIs & device features | No |
| `Access-Control-Allow-Origin` | Scopes cross-origin resource sharing (CORS) | Wildcard = critical |

---

## Sample Test Run — `https://github.com`

The following results were recorded against `https://github.com` during development and represent a typical real-world scan outcome.

| Field | Result |
|---|---|
| **Target URL** | `https://github.com` |
| **Protocol** | HTTPS |
| **HTTP Status** | 200 |
| **Overall Grade** | **B** |
| **Headers Implemented** | 5 / 6 |
| **Critical Risks** | 0 |

### Header-by-header breakdown

| Header | Status | Notes |
|---|---|---|
| `Strict-Transport-Security` | ✅ PRESENT | `max-age=31536000; includeSubdomains; preload` |
| `Content-Security-Policy` | ✅ PRESENT | Directive sources declared |
| `X-Content-Type-Options` | ✅ PRESENT | `nosniff` |
| `X-Frame-Options` | ✅ PRESENT | `deny` |
| `Referrer-Policy` | ✅ PRESENT | `origin-when-cross-origin, strict-origin-when-cross-origin` |
| `Permissions-Policy` | ❌ MISSING | Header not returned — triggers Hardening Recommendation |
| `Access-Control-Allow-Origin` | ⚠️ NOT SET | No CORS header present (not a wildcard, so not a critical risk) |

**Grade rationale:** 5 of 6 headers present = 83 % ratio → **B**. Zero critical risks (CSP absence alone does not count as a critical header in this audit — only `Strict-Transport-Security` and `Content-Security-Policy` are flagged critical, but the CORS header was absent rather than wildcarded, so the critical risk counter stayed at 0, preventing an **F** floor).

### Hardening Recommendations produced

Because Permissions-Policy was missing, the scanner surfaced the following directives under the Hardening Recommendations expander:

**Nginx:**
```nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

**Apache:**
```apache
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

### Export filenames generated

```
websec_github_com_<timestamp>.json
websec_github_com_<timestamp>.csv
```

---

## Role of IBM Bob in Development

[IBM Bob](https://www.ibm.com/products/bob) served as the AI pair programmer throughout the full development lifecycle of this project.

### 🏗️ Scaffolding the Streamlit UI

Bob generated the initial page layout: the four-column metric-card row (`st.columns(4)`), the URL input + button row (`st.columns([5, 1])`), and the placeholder/idle state logic that renders `—` dashes before the first scan is triggered. It also identified `st.markdown(..., unsafe_allow_html=True)` as the correct mechanism for injecting custom HTML card components that Streamlit's native widgets cannot produce.

### 🔍 Writing the Audit Logic

Bob drafted `audit_url()` end-to-end: normalising response headers to lowercase for case-insensitive lookup, iterating the `SECURITY_HEADERS` catalogue to accumulate a `critical_risks` counter, extracting and evaluating the CORS directive for wildcard presence, and assembling the result dict consumed by the UI layer. It also proposed the `compute_grade()` formula including the hard **F** floor for two or more critical risks — a more conservative policy than a pure ratio-based curve.

### 🐛 Fixing the Markdown Badge Rendering Bug

After the badge HTML was written, raw tag text (`</div>`, `<span class="badge badge-missing">MISSING</span>`) was leaking into the rendered page above the CORS section. Bob diagnosed the root cause: Streamlit's Markdown renderer processes each `st.markdown` string as **CommonMark first**, and multi-line triple-quoted f-strings with indented HTML cause the parser to treat intermediate lines as code blocks or literal text before the HTML renderer ever sees them. The fix was to collapse each `st.markdown` call for the header rows into a **single unbroken line** — no embedded newlines or leading whitespace — so the Markdown pass leaves the HTML intact.

### 🔧 Building the Hardening Recommendations Section

Bob authored the `REMEDIATION_DIRECTIVES` constant — a dict mapping each of the seven audited headers to their production-ready Nginx and Apache config directives — and wired up the `st.expander` loop that renders only the directives for headers that are missing or misconfigured in the current scan. It intentionally excludes headers that passed, keeping the output noise-free.

### 📥 Implementing the Export Report Feature

Bob wrote both `build_json_report()` and `build_csv_report()` helper functions, structured the payload to include scanned URL, UTC ISO-8601 timestamp, grade, counts, and a per-header rows array, and connected them to `st.download_button` widgets with auto-stamped filenames derived from the target hostname and scan time. It also proposed the `[1, 1, 4]` column ratio so the two buttons sit flush-left without stretching across the full app width.

### 📐 General Code Quality & Structure

Bob enforced a consistent style throughout: module-level constants (`SECURITY_HEADERS`, `CORS_HEADER`, `REMEDIATION_DIRECTIVES`), pure helper functions (`compute_grade`, `grade_css_class`, `metric_card`, `build_json_report`, `build_csv_report`) separated from the imperative UI layer, and descriptive docstrings on all functions. It also proposed the `{k.lower(): v for k, v in resp.headers.items()}` pattern to normalise the header dict once at ingestion rather than repeating `.lower()` at every lookup site.

---

## License

This project is released under the [MIT License](LICENSE).

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-improvement`.
3. Commit your changes: `git commit -m "Add my improvement"`.
4. Push to the branch: `git push origin feature/my-improvement`.
5. Open a pull request.

---

<p align="center">Built with <a href="https://streamlit.io">Streamlit</a> · Pair-programmed with <a href="https://www.ibm.com/products/bob">IBM Bob</a></p>
