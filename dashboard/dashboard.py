
"""Streamlit dashboard for WebVuln Sentinel.

Displays authorized website security assessment results.
"""

import json
from pathlib import Path

import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="WebVuln Sentinel",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Report loading
# --------------------------------------------------

def load_report():
    """Load the newest timestamped JSON scan report."""

    if not REPORT_DIR.exists():
        return None

    report_files = list(REPORT_DIR.glob("scan_*.json"))

    # Support older reports if no timestamped report exists.
    if not report_files:
        legacy_file = REPORT_DIR / "results.json"

        if legacy_file.exists():
            report_files = [legacy_file]
        else:
            return None

    latest_report = max(
        report_files,
        key=lambda file: file.stat().st_mtime
    )

    try:
        with latest_report.open("r", encoding="utf-8") as file:
            report = json.load(file)

        if isinstance(report, dict):
            report["_report_filename"] = latest_report.name

        return report

    except (json.JSONDecodeError, OSError) as error:
        st.error(f"Could not read the report: {error}")
        return None


def get_results(report):
    """Support both current and older report formats."""

    if isinstance(report, list):
        return report

    if isinstance(report, dict):
        results = report.get("results", [])
        return results if isinstance(results, list) else []

    return []


# --------------------------------------------------
# Risk calculations
# --------------------------------------------------

def risk_counts(results):
    """Calculate risk counts from scan results."""

    levels = ["HIGH", "MEDIUM", "LOW", "REVIEW", "UNKNOWN"]

    counts = {level: 0 for level in levels}

    for result in results:
        risk = result.get("risk", {}).get(
            "risk_level", "UNKNOWN"
        )

        if risk not in counts:
            risk = "UNKNOWN"

        counts[risk] += 1

    return counts


# --------------------------------------------------
# Results table
# --------------------------------------------------

def make_dataframe(results):
    """Convert scan results into a readable table."""

    rows = []

    for result in results:
        risk = result.get("risk", {})

        rows.append({
            "Website": result.get("website", "Unknown"),
            "Final URL": result.get(
                "final_url",
                result.get("website", "Unknown")
            ),
            "Scan Status": result.get("scan_status", "Unknown"),
            "HTTP Status": result.get("http_status", "N/A"),
            "PHP Detected": result.get("php_detected", False),
            "PHP Classification": result.get(
                "php_classification", "Unknown"
            ),
            "PHP Version": result.get("php_version") or "Not disclosed",
            "Assessment": result.get(
                "vulnerability_status", "Not assessed"
            ),
            "Redirect Followed": result.get(
                "redirect_followed", False
            ),
            "Risk Level": risk.get("risk_level", "UNKNOWN"),
            "Priority": risk.get("priority", "N/A")
        })

    return pd.DataFrame(rows)


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def display_list(title, values):
    """Display a list of evidence items."""

    st.write(f"**{title}:**")

    if not values:
        st.write("No information available.")
        return

    for value in values:
        st.write(f"- {value}")


def display_evidence(evidence):
    """Display PHP detection evidence safely."""

    st.write("**Evidence that led to the detection:**")

    if not evidence:
        st.info("No PHP detection evidence was recorded.")
        return

    evidence_rows = []

    for item in evidence:
        evidence_rows.append({
            "Indicator": item.get("indicator", "Unknown"),
            "Source": item.get("source", "Unknown"),
            "Observed Value": item.get("value", "Not available"),
            "Strength": item.get("strength", "Unknown")
        })

    st.dataframe(
        pd.DataFrame(evidence_rows),
        width="stretch",
        hide_index=True
    )


def display_redirect_details(result):
    """Display redirect information for an individual website."""

    st.markdown("#### Redirect Information")

    redirect_detected = result.get("redirect_detected", False)
    redirect_followed = result.get("redirect_followed", False)

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Redirect Detected",
        "Yes" if redirect_detected else "No"
    )

    col2.metric(
        "Redirect Followed",
        "Yes" if redirect_followed else "No"
    )

    col3.metric(
        "Redirect Status",
        result.get("redirect_scope_status", "Not applicable")
    )

    st.write(
        "**Original URL:**",
        result.get("website", "Unknown")
    )

    st.write(
        "**Final URL:**",
        result.get("final_url", "Not available")
    )

    redirect_url = result.get("redirect_url")

    if redirect_url:
        st.write("**Redirect Destination:**", redirect_url)

    redirect_reason = result.get("redirect_reason")

    if redirect_reason:
        st.write("**Redirect Reason:**", redirect_reason)

    redirect_chain = result.get("redirect_chain", [])

    if redirect_chain:
        st.write("**Redirect History:**")

        st.dataframe(
            pd.DataFrame(redirect_chain),
            width="stretch",
            hide_index=True
        )
    else:
        st.write("No redirect history recorded.")


def display_cve_details(result):
    """Display individual CVE assessment results."""

    st.markdown("#### CVE Assessment")

    cve_matches = result.get("cve_matches", [])

    if not cve_matches:
        st.info("No CVE matches available.")
        return

    st.dataframe(
        pd.DataFrame(cve_matches),
        width="stretch",
        hide_index=True
    )


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🛡️ WebVuln Sentinel")

st.markdown("### Authorized Website Security Assessment")

st.caption(
    "A passive PHP security assessment tool that analyzes "
    "publicly disclosed technology information."
)

st.divider()


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("Dashboard Controls")

if st.sidebar.button(
    "🔄 Refresh Report",
    width="stretch"
):
    st.rerun()

st.sidebar.markdown("---")

st.sidebar.info(
    "Run `python -m app.main` in your terminal "
    "to perform a new assessment."
)

st.sidebar.caption(
    "Only scan websites that you own or have explicit "
    "permission to assess."
)


# --------------------------------------------------
# Load report
# --------------------------------------------------

report = load_report()

if report is None:
    st.warning("No report found yet.")

    st.info(
        "Run the scanner first using `python -m app.main`. "
        "The report will appear here after it is generated."
    )

    st.stop()


results = get_results(report)

if not results:
    st.info("The report exists, but it contains no scan results.")
    st.stop()


# --------------------------------------------------
# Summary metrics
# --------------------------------------------------

counts = risk_counts(results)

total_targets = len(results)

completed = sum(
    1 for result in results
    if result.get("scan_status") == "COMPLETED"
)

rejected = sum(
    1 for result in results
    if result.get("scan_status") in (
        "REJECTED",
        "REDIRECT_BLOCKED",
        "REDIRECT_STOPPED"
    )
)

errors = sum(
    1 for result in results
    if result.get("scan_status") == "ERROR"
)

st.subheader("Assessment Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Targets", total_targets)
col2.metric("Completed", completed)
col3.metric("Rejected / Blocked", rejected)
col4.metric("Scan Errors", errors)


# --------------------------------------------------
# Risk distribution
# --------------------------------------------------

st.markdown("#### Risk Distribution")

risk_df = pd.DataFrame({
    "Risk Level": list(counts.keys()),
    "Websites": list(counts.values())
})

st.bar_chart(
    risk_df.set_index("Risk Level"),
    height=250
)

st.divider()


# --------------------------------------------------
# Scan results table
# --------------------------------------------------

st.subheader("Website Scan Results")

df = make_dataframe(results)

available_risks = [
    "All"
] + sorted(df["Risk Level"].unique().tolist())

selected_risk = st.selectbox(
    "Filter by risk level",
    available_risks
)

if selected_risk != "All":
    filtered_df = df[
        df["Risk Level"] == selected_risk
    ]
else:
    filtered_df = df

st.dataframe(
    filtered_df,
    width="stretch",
    hide_index=True
)

st.divider()


# --------------------------------------------------
# Individual website details
# --------------------------------------------------

st.subheader("Detailed Website Assessment")

website_options = [
    f"{index + 1}. {result.get('website', 'Unknown')}"
    for index, result in enumerate(results)
]

selected_option = st.selectbox(
    "Select a website",
    website_options
)

selected_index = website_options.index(selected_option)

selected_result = results[selected_index]

risk = selected_result.get("risk", {})


# --------------------------------------------------
# Assessment summary
# --------------------------------------------------

st.markdown("#### Assessment Summary")

detail_col1, detail_col2, detail_col3 = st.columns(3)

detail_col1.metric(
    "Risk Level",
    risk.get("risk_level", "UNKNOWN")
)

detail_col2.metric(
    "PHP Version",
    selected_result.get("php_version") or "Not disclosed"
)

detail_col3.metric(
    "HTTP Status",
    selected_result.get("http_status", "N/A")
)

st.write(
    "**Scan Status:**",
    selected_result.get("scan_status", "Unknown")
)

st.write(
    "**Vulnerability Assessment:**",
    selected_result.get("vulnerability_status", "Not assessed")
)

st.write(
    "**Reason:**",
    risk.get(
        "reason",
        "No additional assessment available."
    )
)


# --------------------------------------------------
# PHP detection details
# --------------------------------------------------

st.divider()

st.markdown("#### PHP Detection Details")

st.write(
    "**PHP Detected:**",
    "Yes" if selected_result.get("php_detected") else "No"
)

st.write(
    "**Classification:**",
    selected_result.get("php_classification", "Unknown")
)

st.write(
    "**Detection Confidence:**",
    selected_result.get("php_confidence", "Unknown")
)

st.write(
    "**PHP Version Source:**",
    selected_result.get("version_source") or "Not available"
)

display_list(
    "Strong Indicators",
    selected_result.get("strong_indicators", [])
)

display_list(
    "Weak Indicators",
    selected_result.get("weak_indicators", [])
)

display_evidence(
    selected_result.get("evidence", [])
)


# --------------------------------------------------
# HTTP response information
# --------------------------------------------------

st.divider()

st.markdown("#### HTTP Response Information")

http_headers = selected_result.get("http_headers", {})

if http_headers:
    st.write("**HTTP Response Headers:**")

    st.json(http_headers)
else:
    st.info(
        "HTTP response headers were not separately recorded "
        "in this scan result. Check the evidence section above "
        "for headers that contributed to PHP detection."
    )


# --------------------------------------------------
# Redirect information
# --------------------------------------------------

st.divider()

display_redirect_details(selected_result)


# --------------------------------------------------
# CVE information
# --------------------------------------------------

st.divider()

display_cve_details(selected_result)


# --------------------------------------------------
# Complete scan result
# --------------------------------------------------

st.divider()

with st.expander("View Complete Scan Result"):
    st.json(selected_result)


# --------------------------------------------------
# Report information
# --------------------------------------------------

st.divider()

st.subheader("Report Information")

st.write(
    "**Project:**",
    report.get("project", "WebVuln Sentinel")
    if isinstance(report, dict)
    else "WebVuln Sentinel"
)

if isinstance(report, dict):

    st.write(
        "**Report File:**",
        report.get("_report_filename", "Unknown")
    )

    st.write(
        "**Generated At:**",
        report.get("generated_at", "Not available")
    )

    limitations = report.get("limitations", [])

    if limitations:
        with st.expander("Assessment Limitations"):
            for limitation in limitations:
                st.write(f"- {limitation}")


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.caption(
    "WebVuln Sentinel provides preliminary security assessments. "
    "A version match does not confirm an exploitable vulnerability. "
    "Security fixes may also be backported by hosting providers."
)
