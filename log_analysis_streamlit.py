import streamlit as st
import pandas as pd
import re
import matplotlib.pyplot as plt

st.set_page_config(page_title="Log Analyzer Dashboard", layout="wide")
st.title("🔐 Auth Log Analyzer")

# File upload
uploaded_file = st.file_uploader("Upload your auth.log file", type="log")

if uploaded_file:
    # Read and decode file
    lines = uploaded_file.read().decode("utf-8").splitlines()

    # Regex to parse lines
    pattern = re.compile(
        r'(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<service>\w+)\[\d+\]: (?P<action>Accepted|Failed) password for( invalid user)? (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2'
    )

    parsed_logs = [match.groupdict() for line in lines if (match := pattern.search(line))]
    df = pd.DataFrame(parsed_logs)

    if not df.empty:
        st.success("Log file parsed successfully!")
        
        # Show raw data
        with st.expander("🔍 View Raw Parsed Data"):
            st.dataframe(df)

        # Summary stats
        st.subheader("📊 Summary Statistics")
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total Entries", len(df))
            st.metric("Unique IPs", df["ip"].nunique())

        with col2:
            st.metric("Failed Logins", len(df[df["action"] == "Failed"]))
            st.metric("Successful Logins", len(df[df["action"] == "Accepted"]))

        # Bar chart - Top IPs
        st.subheader("🚨 Top IPs by Failed Attempts")
        failed_ips = df[df["action"] == "Failed"]["ip"].value_counts().head(10)
        st.bar_chart(failed_ips)

        # Bar chart - Top Users by Failed Attempts
        st.subheader("👤 Top Users by Failed Attempts")
        failed_users = df[df["action"] == "Failed"]["user"].value_counts().head(10)
        st.bar_chart(failed_users)

        # Optional: Add time-series chart (if timestamp is needed as datetime)
        # You could enhance this by converting timestamp to real datetime

    else:
        st.warning("No valid log lines parsed from the file.")
else:
    st.info("Please upload an auth.log file to begin analysis.")
