
import streamlit as st
import pandas as pd
import plotly.express as px

# Set up the page
st.set_page_config(
    page_title="Digital Forensics Log Analyzer",
    page_icon="🔎🕵️❗",
    layout="wide"
)

st.title("🔎 Digital Forensics Log Analyzer")

st.write(
    "This app lets users explore login records and look for "
    "unusual activity, like repeated failed logins or a "
    "successful login after multiple failed attempts."
)

# Load the CSV file
st.sidebar.header("Upload Log Data")

uploaded_file = st.sidebar.file_uploader(
    "Upload a CSV file",
    type=["csv"]
)

try:
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
    else:
        df = pd.read_csv("authentication_logs.csv")
except Exception as e:
    st.error(f"Could not read the CSV file: {e}")
    st.stop()

# Check that the CSV has the right columns
required_columns = {
    "timestamp", "username", "ip_address", "status"
}

if not required_columns.issubset(df.columns):
    st.error(
        "CSV must contain timestamp, username, "
        "ip_address, and status."
    )
    st.stop()

df["timestamp"] = pd.to_datetime(
    df["timestamp"], errors="coerce"
)

df = df.dropna(
    subset=["timestamp", "username", "ip_address"]
).copy()

df["status"] = (
    df["status"].astype(str).str.strip().str.title()
)

df = df[df["status"].isin(["Success", "Failed"])].copy()

if df.empty:
    st.warning("There are no valid login records to display.")
    st.stop()

# Filter the login records
st.sidebar.header("Investigation Filters")

status_filter = st.sidebar.selectbox(
    "Login Status",
    ["All", "Success", "Failed"]
)

username_filter = st.sidebar.selectbox(
    "Username",
    ["All"] + sorted(
        df["username"].astype(str).unique().tolist()
    )
)

filtered_df = df.copy()

if status_filter != "All":
    filtered_df = filtered_df[
        filtered_df["status"] == status_filter
    ]

if username_filter != "All":
    filtered_df = filtered_df[
        filtered_df["username"] == username_filter
    ]

# Set up the tabs
tab1, tab2, tab3 = st.tabs([
    "Overview", "Log Explorer", "Investigation"
])

# Overview of login activity
with tab1:
    st.header("Authentication Overview")

    st.write(
        "This section shows the total number of login attempts, "
        "successful and failed logins, and unique IP addresses."
    )

    total = len(filtered_df)
    failed = (filtered_df["status"] == "Failed").sum()
    successful = (filtered_df["status"] == "Success").sum()
    unique_ips = filtered_df["ip_address"].nunique()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Attempts", total)
    col2.metric("Failed Logins", failed)
    col3.metric("Successful Logins", successful)
    col4.metric("Unique IPs", unique_ips)

    st.subheader("Login Attempts by Status")

    counts = (
        filtered_df["status"]
        .value_counts()
        .rename_axis("Status")
        .reset_index(name="Attempts")
    )

    if not counts.empty:
        fig = px.bar(
            counts,
            x="Status",
            y="Attempts",
            color="Status",
            title="Successful vs. Failed Login Attempts",
            labels={
                "Status": "Login Status",
                "Attempts": "Number of Attempts"
            },
            color_discrete_map={
                "Failed": "#C2185B",
                "Success": "#F8BBD0"
            }
        )

        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#FFEAF4"
        )

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("No records match your filters.")


# Display the login records
with tab2:
    st.header("Authentication Log Explorer")

    st.write(
        "Here, you can look through individual login records "
        "and use the sidebar filters to focus on specific activity."
    )

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )


# Check for unusual login activity
with tab3:
    st.header("Login Investigation")

    st.write(
        "Here, you can see which IP addresses have the most "
        "failed login attempts and check for patterns that "
        "might need further investigation."
    )

    # Use all login results to check for patterns
    investigation_df = df.copy()

    if username_filter != "All":
        investigation_df = investigation_df[
            investigation_df["username"] == username_filter
        ]

    # Set the number of failed attempts to flag
    threshold = st.slider(
        "Minimum failed attempts to flag an IP",
        min_value=1,
        max_value=10,
        value=3
    )

    # Get failed logins
    failed_logs = investigation_df[
        investigation_df["status"] == "Failed"
    ]

    # Count failed attempts per IP
    ip_counts = (
        failed_logs.groupby("ip_address")
        .size()
        .reset_index(name="Failed Attempts")
        .sort_values("Failed Attempts", ascending=False)
    )

    st.subheader("Failed Logins by IP Address")

    if not ip_counts.empty:
        fig = px.bar(
            ip_counts,
            x="ip_address",
            y="Failed Attempts",
            color="Failed Attempts",
            title="Failed Authentication Attempts by IP",
            labels={
                "ip_address": "IP Address",
                "Failed Attempts": "Number of Failed Logins"
            },
            color_continuous_scale=[
                "#FFD1E8",
                "#FF9BC5",
                "#FF5CA8",
                "#E91E63",
                "#AD1457"
            ]
        )

        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#FFEAF4",
            coloraxis_colorbar_title="Failed Attempts",
            xaxis={"categoryorder": "total descending"}
        )

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("No failed login attempts were found.")

    # Find IPs with repeated failed logins
    suspicious = ip_counts[
        ip_counts["Failed Attempts"] >= threshold
    ].copy()

    st.subheader("Investigation Results")

    if suspicious.empty:
        st.success(
            "No IP addresses meet the selected threshold."
        )

    else:
        st.warning(
            f"{len(suspicious)} IP address(es) "
            "need further investigation."
        )

        findings = []

        for _, row in suspicious.iterrows():
            ip = row["ip_address"]
            failures = int(row["Failed Attempts"])

            # Check the login history for this IP
            ip_events = investigation_df[
                investigation_df["ip_address"] == ip
            ].sort_values("timestamp")

            success_after_failure = False

            # Check each account separately
            for username, user_events in ip_events.groupby("username"):
                failed_count = 0

                for _, event in user_events.iterrows():
                    if event["status"] == "Failed":
                        failed_count += 1

                    elif event["status"] == "Success":
                        if failed_count >= threshold:
                            success_after_failure = True

                        failed_count = 0

            if success_after_failure:
                finding = (
                    "Repeated failed logins followed "
                    "by a successful login"
                )
            else:
                finding = "Repeated failed login attempts"

            findings.append({
                "IP Address": ip,
                "Failed Attempts": failures,
                "Finding": finding
            })

        findings_df = pd.DataFrame(findings)

        # Show the results
        col1, col2 = st.columns(2)

        col1.metric(
            "Flagged IP Addresses",
            len(findings_df)
        )

        col2.metric(
            "Total Flagged Failures",
            int(findings_df["Failed Attempts"].sum())
        )

        st.dataframe(
            findings_df,
            use_container_width=True,
            hide_index=True
        )

        # Download results
        csv_report = findings_df.to_csv(index=False)

        st.download_button(
            label="Download Investigation Report",
            data=csv_report,
            file_name="investigation_report.csv",
            mime="text/csv"
        )

    st.info(
        "These results show patterns worth looking into, "
        "but they don't necessarily mean an attack happened."
    )

st.caption(
    "This project uses sample authentication logs for educational purposes."
)
