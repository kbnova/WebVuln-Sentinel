
"""Streamlit dashboard for WebVuln Sentinel."""

import json
from pathlib import Path

import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_FILE = BASE_DIR / "reports" / "results.json"


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
    """Load the latest JSON scan report."""
    if not REPORT_FILE.exists():
        return None

    try:
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError) as error:
        st.error(f"Could not read the report: {error}")
        return None


def get_results(report):
    """Support both the current report format and older list format."""
    if isinstance(report, list):
        return report

    if isinstance(report, dict):
        results = report.get("results", [])
        return results if isinstance(results, list) else []

    return []


def risk_counts(results):
    """Calculate risk counts from individual scan results."""
    levels = ["HIGH", "MEDIUM", "LOW", "REVIEW", "UNKNOWN"]

    counts = {level: 0 for level in levels}

    for result in results:
        risk = result.get("risk", {}).get("risk_level", "UNKNOWN")

        if risk not in counts:
            risk = "UNKNOWN"

        counts[risk] += 1

    return counts


def make_dataframe(results):
    """Convert scan results into a readable table."""
    rows = []

    for result in results:
        risk = result.get("risk", {})

        rows.append({
            "Website": result.get("website", "Unknown"),
            "Scan Status": result.get("scan_status", "Unknown"),
            "HTTP Status": result.get("http_status", "N/A"),
            "PHP Detected": result.get("php_detected", False),
            "PHP Version": result.get("php_version") or "Not disclosed",
            "Assessment": result.get(
                "vulnerability_status",
                "Not assessed"
            ),
            "Risk Level": risk.get("risk_level", "UNKNOWN"),
            "Priority": risk.get("priority", "N/A")
        })

    return pd.DataFrame(rows)


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("🛡️ WebVuln Sentinel")

st.markdown(
    "### Authorized Website Security Assessment"
)

st.caption(
    "A passive PHP security assessment tool that analyzes "
    "publicly disclosed technology information."
)

st.divider()


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("Dashboard Controls")

if st.sidebar.button("🔄 Refresh Report", use_container_width=True):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.info(
    "Run `python -m app.main` in your terminal "
    "to perform a new assessment."
)

st.sidebar.caption(
    "Only scan websites that you own or have explicit permission to assess."
)


# --------------------------------------------------
# Load report
# --------------------------------------------------

report = load_report()

if report is None:
    st.warning("No report found yet.")
    st.info(
        "Run the scanner first using `python -m app.main`. "
        "The report will appear here automatically after it is generated."
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
    if result.get("scan_status") == "REJECTED"
)
errors = sum(
    1 for result in results
    if result.get("scan_status") == "ERROR"
)

st.subheader("Assessment Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Targets", total_targets)
col2.metric("Completed", completed)
col3.metric("Rejected", rejected)
col4.metric("Scan Errors", errors)

st.markdown("#### Risk Distribution")

risk_df = pd.DataFrame(
    {
        "Risk Level": list(counts.keys()),
        "Websites": list(counts.values())
    }
)

st.bar_chart(
    risk_df.set_index("Risk Level"),
    height=250
)

st.divider()


# --------------------------------------------------
# Scan results
# --------------------------------------------------

st.subheader("Website Scan Results")

df = make_dataframe(results)

available_risks = ["All"] + sorted(df["Risk Level"].unique().tolist())

selected_risk = st.selectbox(
    "Filter by risk level",
    available_risks
)

if selected_risk != "All":
    filtered_df = df[df["Risk Level"] == selected_risk]
else:
    filtered_df = df

st.dataframe(
    filtered_df,
    use_container_width=True,
    hide_index=True
)


# --------------------------------------------------
# Individual website details
# --------------------------------------------------

st.divider()
st.subheader("Detailed Assessment")

website_options = [
    result.get("website", f"Target {index + 1}")
    for index, result in enumerate(results)
]

selected_website = st.selectbox(
    "Select a website",
    website_options
)

selected_result = next(
    (
        result for result in results
        if result.get("website") == selected_website
    ),
    None
)

if selected_result:
    risk = selected_result.get("risk", {})

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

    st.write("**Reason:**")
    st.write(risk.get("reason", "No additional assessment available."))

    st.write("**Detected Indicators:**")
    indicators = selected_result.get("indicators", [])

    if indicators:
        for indicator in indicators:
            st.write(f"- {indicator}")
    else:
        st.write("No PHP indicators were detected.")

    st.write("**CVE Assessment:**")

    cve_matches = selected_result.get("cve_matches", [])

    if cve_matches:
        st.dataframe(
            pd.DataFrame(cve_matches),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.write("No CVE matches available.")

    with st.expander("View complete scan result"):
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
        "**Generated At:**",
        report.get("generated_at", "Not available")
    )

    limitations = report.get("limitations", [])

    if limitations:
        with st.expander("Assessment Limitations"):
            for limitation in limitations:
                st.write(f"- {limitation}")

st.caption(
    "WebVuln Sentinel provides preliminary security assessments. "
    "A version match is not confirmation of an exploitable vulnerability."
)
