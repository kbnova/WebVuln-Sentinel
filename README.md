
# WebVuln Sentinel

### Passive PHP Security Assessment Scanner

WebVuln Sentinel is a Python-based security assessment tool
designed to identify publicly exposed PHP version information
on authorized websites and compare it against configured
security advisories.

It provides preliminary security assessments and generates
structured JSON reports with an interactive Streamlit dashboard.

**Important:** A potential version match is not proof that a
website is vulnerable. The tool does not perform exploitation.

---

## Features

- Authorized-domain validation.
- HTTP response analysis.
- PHP version detection.
- PHP security advisory and CVE matching.
- Preliminary risk classification.
- JSON report generation.
- Interactive Streamlit dashboard.
- Automated testing with pytest.

## Technology Stack

- Python
- Requests
- Streamlit
- Pandas
- Pytest
- JSON

## Project Structure

```text
WebVuln-Sentinel/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── scanner.py
│   ├── php_detector.py
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
│
├── tests/
│   ├── test_scanner.py
│   ├── test_php_detector.py
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

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd WebVuln-Sentinel
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Configuration

### 1. Configure authorized domains

Edit `config/scope.json`:

```json
{
    "authorized_domains": [
        "your-authorized-domain.com"
    ],
    "allow_subdomains": false,
    "max_targets": 10,
    "request_timeout": 8,
    "follow_redirects": false
}
```

Replace the example domain with a domain you own or have
explicit permission to assess.

### 2. Add target URLs

Edit `data/targets.txt`:

```text
https://your-authorized-domain.com
```

Only add authorized targets.

## Running the Scanner

From the project root:

```bash
python -m app.main
```

The scanner will process the configured targets and generate
a JSON assessment report.

Report location:

```text
reports/results.json
```

## Running the Dashboard

Start the Streamlit dashboard:

```bash
streamlit run dashboard/dashboard.py
```

Open the local address displayed in your terminal,
usually:

```text
http://localhost:8501
```

The dashboard displays assessment summaries, risk levels
and individual scan details.

## Running Automated Tests

Run all tests:

```bash
python -m pytest -v
```

## Vulnerability Intelligence

The current rules include:

- CVE-2026-109618
- CVE-2026-109619

The configured version thresholds are maintained in:

```text
data/vulnerability_rules.json
```

Refer to the official PHP security advisories:

https://www.php.net/archive/2026.php

## Security Disclaimer

This project is intended for authorized defensive security
assessment and educational purposes.

- Do not scan websites without permission.
- A detected PHP version does not prove vulnerability.
- Hosting providers may backport security fixes.
- Hidden PHP version information does not mean a website
  is secure.
- The scanner does not exploit vulnerabilities.
- Further DNS-rebinding and network security hardening
  is required before production use.

## Current Project Status

Development prototype.

The current implementation supports authorized target
validation, passive PHP indicator detection, configured
CVE matching, preliminary risk assessment and JSON reporting.

Further integration testing, security hardening and
deployment validation are required.

## License

To be added before public release.
