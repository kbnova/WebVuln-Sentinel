# WebVuln Sentinel

### Passive PHP Security Assessment Scanner

WebVuln Sentinel is a Python-based passive security assessment tool designed to identify publicly exposed PHP version information on authorized websites and compare detected versions against configured security advisories.

The project uses HTTP response analysis, PHP fingerprint detection, version comparison, and preliminary risk classification to generate structured JSON security assessment reports.

It also provides an interactive Streamlit dashboard for reviewing scan results.

**Important:** A detected version match indicates a potential security concern, not proof that a website is exploitable. The scanner does not perform exploitation or intrusive vulnerability verification.

---

## Features

### 1. Authorized Target Validation
- Validates target domains against configured authorization rules.
- Restricts scanning to explicitly authorized domains.
- Supports configurable subdomain and target-count restrictions.

### 2. Safe HTTP Assessment
- Analyzes HTTP responses from authorized targets.
- Uses DNS resolution checks and IP validation.
- Pins connections to validated IP addresses to reduce DNS-rebinding risks.
- Applies request timeouts and redirect limits.

### 3. Redirect Scope Protection
- Follows redirects only when the destination is authorized.
- Records out-of-scope redirect destinations.
- Stops scanning when a redirect leads outside the authorized scope.
- Records whether a redirect was followed.

### 4. PHP Fingerprint Detection
- Identifies PHP indicators from HTTP response headers.
- Checks PHP-related cookie names without exposing cookie values.
- Analyzes PHP-specific file references and runtime evidence.
- Avoids treating generic fatal or parse errors alone as proof of PHP.

### 5. Vulnerability Assessment
- Compares detected PHP versions against configured security rules.
- Assesses individual CVE advisories independently.
- Identifies configured end-of-life PHP branches.
- Flags older branches requiring vendor verification.

### 6. Preliminary Risk Classification
- Classifies findings into risk categories.
- Distinguishes potential version matches from confirmed vulnerabilities.
- Accounts for uncertainty and vendor backported security fixes.

### 7. JSON Reporting
- Generates structured JSON assessment reports.
- Saves each scan as a separate timestamped report.
- Preserves previous scan reports instead of overwriting them.

### 8. Interactive Dashboard
- Displays scan summaries and risk classifications.
- Shows PHP version and detection evidence.
- Displays relevant HTTP header and cookie-name evidence.
- Presents individual CVE assessment results.
- Shows redirect information and report details.

### 9. Automated Testing
- Includes automated unit and integration-style tests using pytest.
- Tests target validation, PHP detection, CVE assessment, redirects, and report generation.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and scanner |
| Requests | HTTP communication |
| Streamlit | Interactive dashboard |
| Pandas | Dashboard data handling |
| JSON | Configuration, vulnerability rules, and reports |
| Pytest | Automated testing |

---

## Project Structure

```text
WebVuln-Sentinel/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── scanner.py
│   ├── version_checker.py
│   ├── cve_checker.py
│   ├── risk_analyzer.py
│   ├── report_generator.py
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   └── php_fingerprints.py
│   │
│   └── discovery/
│       ├── __init__.py
│       ├── base.py
│       ├── discovery_engine.py
│       └── crtsh_provider.py
│
├── config/
│   └── scope.json
│
├── dashboard/
│   └── dashboard.py
│
├── data/
│   ├── targets.txt
│   └── vulnerability_rules.json
│
├── docs/
│   └── architecture.md
│
├── reports/
│   └── (generated JSON reports)
│
├── tests/
│   ├── test_scanner.py
│   ├── test_php_fingerprints.py
│   ├── test_version_checker.py
│   ├── test_cve_checker.py
│   ├── test_report_generator.py
│   ├── test_discovery.py
│   └── test_discovery_engine.py
│
├── .gitignore
├── README.md
├── requirements.txt
└── pytest.ini
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/kbnova/WebVuln-Sentinel.git
cd WebVuln-Sentinel
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## Configuration

### 1. Configure authorized domains

Edit:

```text
config/scope.json
```

Add only domains that you own or have explicit permission to assess.

Example:

```json
{
    "authorized_domains": [
        "your-authorized-domain.com"
    ]
}
```

**Note:** This is an illustrative example, not a replacement for your existing configuration. Preserve the other settings required by your scanner.

### 2. Add target URLs

Edit:

```text
data/targets.txt
```

Example:

```text
https://your-authorized-domain.com
```

Only include authorized target URLs.

---

## Running the Scanner

Run the scanner from the project root:

```bash
python -m app.main
```

The scanner processes the configured targets and generates a structured JSON assessment report.

### Report Storage

Reports are stored in:

```text
reports/
```

Each scan generates a separate timestamped JSON file.

Example:

```text
reports/
├── scan_20261105_120000_123456.json
├── scan_20261105_130000_456789.json
└── scan_20261105_140000_789012.json
```

The actual filenames are generated automatically. Existing reports are preserved.

---

## Running the Dashboard

Start the Streamlit dashboard:

```bash
streamlit run dashboard/dashboard.py
```

Open the local address displayed in your terminal, usually:

```text
http://localhost:8501
```

The dashboard provides:

- Overall scan summary.
- Target-wise assessment results.
- Detected PHP versions and their evidence.
- Relevant HTTP response headers and cookie names.
- Individual CVE assessment results.
- End-of-life version warnings.
- Redirect status and scope information.
- Risk classifications.
- Report details.

The dashboard reads the generated scan reports from the `reports/` directory.

---

## Running Automated Tests

Run the complete test suite:

```bash
python -m pytest -v
```

The tests cover the scanner, PHP fingerprint detection, version comparison, CVE assessment, redirect handling, report generation, and discovery functionality.

---

## Vulnerability Intelligence

The current vulnerability rules include:

- **CVE-2026-109618** — PHP Remote Code Execution via Out-of-Memory Corruption.
- **CVE-2026-109619** — PHP Remote Code Execution via Stale Global State.

The vulnerability rules are maintained in:

```text
data/vulnerability_rules.json
```

Each advisory is assessed independently using its configured fixed-version thresholds.

The configuration also includes selected end-of-life PHP branches that require additional vendor verification.

### Official Reference

PHP security advisories:

https://www.php.net/archive/2026.php

---

## Security Considerations and Limitations

WebVuln Sentinel is intended for authorized defensive security assessment and educational purposes.

- Do not scan websites without explicit permission.
- A detected PHP version does not prove that a vulnerability is exploitable.
- Hosting providers may backport security fixes without changing the publicly detected version.
- Some websites do not expose PHP version information.
- End-of-life PHP branches may require additional vendor-specific verification.
- Cookie values and sensitive session data should not be exposed in assessment reports.
- DNS validation and connection pinning reduce certain DNS-rebinding risks but do not constitute a complete production-grade network security solution.
- The scanner does not execute exploits or perform intrusive vulnerability verification.

The project remains a development prototype and requires further independent security review and deployment validation before production use.

---

## Current Project Status

**Status: Development Prototype**

The current implementation supports:

- Authorized target validation.
- Passive PHP fingerprint detection.
- PHP version identification.
- Configurable CVE assessment.
- End-of-life PHP branch identification.
- Preliminary risk classification.
- DNS validation and connection pinning.
- Redirect scope protection.
- Timestamped JSON report generation.
- Interactive Streamlit dashboard.
- Automated testing with pytest.

Further integration testing, security review, and deployment validation are recommended.

---

## License

To be added before public release.