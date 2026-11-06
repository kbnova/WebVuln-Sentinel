# WebVuln Sentinel - Architecture

## 1. Project Overview

WebVuln Sentinel is a Python-based, passive PHP security assessment tool. It examines authorized websites for publicly exposed PHP indicators and compares detected PHP versions against configured security advisories.

The application does not exploit vulnerabilities, execute remote commands, or attempt to gain unauthorized access.

## 2. System Architecture

```text
          Authorized Target List
               data/targets.txt
                      |
                      v
               Main Application
                 app/main.py
                      |
                      v
             Scope and URL Validation
                app/scanner.py
                      |
                      v
              HTTP Response Analysis
                      |
                      v
                PHP Fingerprinting
          app/detection/php_fingerprints.py
                      |
                      v
                PHP Version Checking
              app/version_checker.py
                      |
                      v
                  CVE Assessment
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
             Timestamped JSON Reports
                   reports/
                      |
                      v
              Streamlit Dashboard
             dashboard/dashboard.py
```

## 3. Main Components

### Main Application
File: `app/main.py`

Loads configured targets and authorization scope, coordinates website assessments, and saves the resulting reports.

### Scanner
File: `app/scanner.py`

Validates target URLs, checks authorization scope, performs controlled HTTP requests, analyzes responses, and handles redirects. Redirects are followed only when the destination is authorized.

### PHP Fingerprinting
File: `app/detection/php_fingerprints.py`

Identifies PHP-related evidence using HTTP headers, cookie names, and PHP-specific response indicators. Generic server errors alone are not treated as proof of PHP.

### Version Checker
File: `app/version_checker.py`

Evaluates detected PHP versions against configured version thresholds and identifies branches that require additional end-of-life or vendor verification.

### CVE Checker
File: `app/cve_checker.py`

Assesses configured security advisories independently using their respective affected-version rules. A potential version match is not treated as proof of an exploitable vulnerability.

### Risk Analyzer
File: `app/risk_analyzer.py`

Assigns preliminary risk levels and review priorities based on the available assessment evidence.

### Report Generator
File: `app/report_generator.py`

Creates structured JSON reports containing website assessment results, evidence, redirect information, risk summaries, and limitations. Each scan is saved separately to avoid overwriting previous reports.

### Discovery
Files: `app/discovery/`

Contains website discovery functionality, including certificate-transparency-based discovery and the discovery engine. Discovered targets must still pass authorization and scope validation before assessment.

### Dashboard
File: `dashboard/dashboard.py`

Uses Streamlit to display scan summaries, PHP detection evidence, HTTP headers, cookie information, redirect status, CVE assessments, and individual website results.

## 4. Configuration and Data

- `config/scope.json`: Defines authorized domains and scanning limits.
- `data/targets.txt`: Contains configured target URLs.
- `data/vulnerability_rules.json`: Stores configured vulnerability advisories and version assessment rules.
- `reports/`: Stores generated JSON assessment reports.

## 5. Testing

Automated tests are maintained in the `tests/` directory.

Run the complete test suite:

```bash
python -m pytest -v
```

## 6. Security Limitations

- Only explicitly authorized websites should be assessed.
- URL validation and scope checks restrict the scanner to authorized public targets.
- PHP version information may be hidden, incomplete, or inaccurate.
- A PHP-related indicator does not necessarily prove the exact server-side runtime.
- WordPress assets alone do not confirm PHP usage.
- Vendor-backported security fixes may not be reflected by upstream version comparisons.
- A potential CVE version match does not confirm exploitation or vulnerability.
- End-of-life and vendor-specific security status may require independent verification.
- The application does not perform exploit verification.
- DNS and network protections should continue to be reviewed and hardened.

## 7. Future Improvements

- Stronger DNS and network security controls.
- Controlled local PHP vulnerability lab integration.
- Additional verified vulnerability intelligence sources.
- CSV export and historical reporting.
- Improved dashboard filtering and visualization.
- Reproducible installation and deployment.
