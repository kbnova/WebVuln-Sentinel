
WebVuln Sentinel — Architecture

1. Project Overview

WebVuln Sentinel is a Python-based, passive PHP security assessment
tool. It checks authorized websites for publicly exposed PHP
version information and compares detected versions against
configured security advisories.

The application does not exploit vulnerabilities or execute
remote commands.

2. System Architecture

```text
        Authorized Target List
             data/targets.txt
                    |
                    v
              Main Application
               app/main.py
                    |
                    v
             Scope Validation
              app/scanner.py
                    |
                    v
            HTTP Response Analysis
                    |
                    v
              PHP Detection
           app/php_detector.py
                    |
                    v
             Version Checking
          app/version_checker.py
                    |
                    v
               CVE Matching
             app/cve_checker.py
                    |
                    v
              Risk Analysis
            app/risk_analyzer.py
                    |
                    v
             Report Generation
          app/report_generator.py
                    |
                    v
             reports/results.json
                    |
                    v
           Streamlit Dashboard
          dashboard/dashboard.py


3. Main Components

Main Application
File: `app/main.py`

Loads authorized targets, starts the scanning process and
generates the final assessment report.

Scanner
File: `app/scanner.py`

Performs URL validation, checks the configured authorization
scope and retrieves limited HTTP response information.

PHP Detector
File: `app/php_detector.py`

Identifies publicly exposed PHP indicators from HTTP headers,
cookies and response content.

Version Checker
File: `app/version_checker.py`

Compares detected PHP versions with configured upstream
fixed-version thresholds.

CVE Checker
File: `app/cve_checker.py`

Matches PHP version assessments against configured CVE records.

Risk Analyzer
File: `app/risk_analyzer.py`

Assigns a preliminary risk level and review priority.

Report Generator
File: `app/report_generator.py`

Generates structured JSON reports containing scan results,
risk summaries and assessment limitations.

Dashboard
File: `dashboard/dashboard.py`

Displays assessment summaries, risk distribution and
individual scan results using Streamlit.

4. Configuration

- `config/scope.json`: Defines authorized domains and scan limits.
- `data/targets.txt`: Contains the target URLs.
- `data/vulnerability_rules.json`: Stores CVE records and
  upstream fixed-version thresholds.

5. Testing

Automated tests are maintained inside the `tests/` directory.

Run the complete test suite:

```bash
python -m pytest -v
```

6. Security Limitations

- Only authorized websites should be assessed.
- PHP version information may be hidden or inaccurate.
- WordPress assets alone do not confirm PHP usage.
- Vendor backported security fixes may not be reflected
  by upstream version comparisons.
- A potential version match does not confirm exploitation
  or vulnerability.
- DNS rebinding protection requires further hardening.
- The application does not perform exploit verification.

7. Future Improvements

- Stronger DNS and network security controls.
- Controlled local PHP vulnerability lab integration.
- Additional CVE intelligence sources.
- CSV and historical reporting.
- Improved dashboard filtering and visualization.
- Reproducible installation and deployment.
