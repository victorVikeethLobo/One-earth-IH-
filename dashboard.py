import streamlit as st
import json
import pandas as pd

st.title("IDS Alerts Dashboard")

try:
    with open('alerts.json', 'r') as f:
        alerts = json.load(f)
    
    if alerts:
        df = pd.DataFrame(alerts)
        st.dataframe(df)
    else:
        st.write("No alerts detected.")

except FileNotFoundError:
    st.error("alerts.json not found. Please run ids_mock.py first.")
    
except json.JSONDecodeError:
    st.error("Error decoding alerts.json. The file might be corrupted.")