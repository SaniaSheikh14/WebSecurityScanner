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
| **Python 3.10+** | Runtime language |
| **Streamlit ≥ 1.28** | Web UI framework — layout, widgets, download buttons |
| **Requests ≥ 2.31** | HTTP header fetching with redirect support |
| **Pandas ≥ 2.0** | Dependency (available for future tabular analysis) |
| **IBM Bob** | AI pair programmer — UI scaffolding, bug fixing, remediation snippets (see dedicated section below) |

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10 + |
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

The following results were recorded against `https://github.com` during development.

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
| `Content-Security-Policy` | ✅ PRESENT | Declared directive sources returned |
| `X-Content-Type-Options` | ✅ PRESENT | `nosniff` |
| `X-Frame-Options` | ✅ PRESENT | `deny` |
| `Referrer-Policy` | ✅ PRESENT | `origin-when-cross-origin, strict-origin-when-cross-origin` |
| `Permissions-Policy` | ❌ MISSING | No header returned — triggers Hardening Recommendation |
| `Access-Control-Allow-Origin` | ⚠️ NOT SET | Header absent — not a wildcard, so not a critical risk |

**Grade rationale:** 5 of 6 headers present = 83 % ratio → **B**. `Permissions-Policy` is classified `critical: False` in the `SECURITY_HEADERS` catalogue, so its absence does not increment `critical_risks`. The CORS header is absent rather than wildcarded, keeping `critical_risks` at 0. No F floor is applied; the 83 % ratio maps to grade **B**.

### Hardening Recommendation produced

Because `Permissions-Policy` was missing, the scanner surfaced the following directives under the **🔧 Hardening Recommendations** expander:

**Nginx** — add inside your `server {}` or `location {}` block:

```nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

**Apache** — add inside `<VirtualHost>` or `.htaccess` (requires `mod_headers`):

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

### 🏗️ Scaffolding the Streamlit Layout & Metric Cards

Bob generated the foundational Streamlit layout: the four-column metric-card row (`st.columns(4)`), the URL input + button row (`st.columns([5, 1])`), and the idle-state logic that pre-renders `—` dash values in the metric cards before any scan is triggered. It identified `st.markdown(..., unsafe_allow_html=True)` as the correct mechanism for injecting custom HTML card components that Streamlit's native widgets cannot produce, and specified targeting Streamlit's internal `[data-testid="stAppViewContainer"]` attribute selector (rather than `body`) for the dark-theme CSS overrides.

### 🐛 Resolving Streamlit Markdown Badge Unrendered HTML Bug

After the per-header badge HTML was written, raw tag text (`</div>`, `<span class="badge badge-missing">MISSING</span>`) leaked as visible plain text into the page above the CORS section. Bob diagnosed the root cause: Streamlit's `st.markdown()` passes strings through a **CommonMark parser first**, before the HTML renderer runs. Multi-line triple-quoted f-strings with indented HTML cause the parser to emit intermediate lines as code blocks or literal text. The fix was collapsing every `st.markdown` call containing multi-element HTML into a **single unbroken line** — no embedded newlines — so the Markdown pre-processor leaves the HTML intact. The `unsafe_allow_html=True` parameter was already correctly set; only the string format needed changing.

### 🌐 Custom User-Agent Injection

During testing, certain domains behind Cloudflare and similar bot-management platforms returned `403 Forbidden` responses to Python's default `requests` User-Agent string (`python-requests/2.x.x`). Bob identified this as a surface-level bot filter and proposed injecting a browser-like User-Agent header in the `requests.get` call to keep audits passive and non-intrusive while bypassing the filter:

```python
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
resp = requests.get(url, timeout=10, allow_redirects=True,
                    headers={"User-Agent": BROWSER_UA})
```

### 🔧 Generating Remediation Snippets & Export Routines

Bob authored the entire `REMEDIATION_DIRECTIVES` constant — mapping each of the seven audited headers to production-ready Nginx and Apache config directives — and wired up the `st.expander` loop that renders directives only for missing headers, keeping the output noise-free. It also specified using `always` in Nginx directives to ensure headers are sent on error responses (4xx/5xx), not just 2xx. For the export module, Bob drafted both `build_json_report()` and `build_csv_report()`, structured the JSON payload for SIEM-parseable output, and proposed the `[1, 1, 4]` column ratio for the download button row.

### 📐 Code Quality & Structure

Bob enforced consistent style throughout: module-level constants (`SECURITY_HEADERS`, `CORS_HEADER`, `REMEDIATION_DIRECTIVES`), pure helper functions (`compute_grade`, `grade_css_class`, `metric_card`, `build_json_report`, `build_csv_report`) separated from the imperative UI layer, and descriptive docstrings. It also proposed the `{k.lower(): v for k, v in resp.headers.items()}` pattern to normalise response headers once at ingestion rather than repeating `.lower()` at every lookup site.

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
