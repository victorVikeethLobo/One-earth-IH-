# app_v5.py -- One-Earth Unified IoT Security Dashboard (V5 - State-Managed Tabs)
import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
import json
import time
import datetime
import random
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from sklearn.ensemble import IsolationForest
from streamlit_autorefresh import st_autorefresh
import altair as alt

# ---------------------------------------------------------------------
# 1. CONFIGURATION & CONSTANTS
# ---------------------------------------------------------------------
# NOTE: In a real-world app, use st.secrets or environment variables for sensitive info.
ADMIN_PASSPHRASE = "admin123" 
DB_FILE = "oneearth_v5.db"
SENSOR_IDS = [f"S{i:02d}" for i in range(1, 6)]
IDS_THRESHOLDS = {
    "temperature": {"max": 50.0, "min": -10.0}, 
    "air_quality": {"max": 150.0}, 
    "water_level": {"min": 0.1}
}

# Page configuration should be the first Streamlit command
st.set_page_config(
    page_title="One-Earth IoT Security",
    page_icon="🌍",
    layout="wide"
)

# ---------------------------------------------------------------------
# 2. BLOCKCHAIN SIMULATION CLASSES
# ---------------------------------------------------------------------
class Block:
    """Represents a single block in our simulated blockchain."""
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the SHA-256 hash of the block."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "prev_hash": self.prev_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    """Manages the chain of blocks."""
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        """Creates the very first block in the chain."""
        return Block(0, str(datetime.datetime.now()), "Genesis Block", "0")

    def get_latest_block(self):
        """Returns the most recent block."""
        return self.chain[-1]

    def add_block(self, data):
        """Mines and adds a new block to the chain."""
        prev_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=str(datetime.datetime.now()),
            data=data,
            prev_hash=prev_block.hash
        )
        self.chain.append(new_block)
    
    def is_chain_valid(self):
        """
        Validates the integrity of the entire blockchain.
        Checks if each block's previous_hash correctly points to the hash of the block before it.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            prev_block = self.chain[i-1]
            if current_block.hash != current_block.calculate_hash():
                return False, f"Block {current_block.index} hash is corrupt."
            if current_block.prev_hash != prev_block.hash:
                return False, f"Chain broken at Block {current_block.index}."
        return True, "Chain integrity verified."

# ---------------------------------------------------------------------
# 3. CORE HELPERS & DATABASE FUNCTIONS
# ---------------------------------------------------------------------
@st.cache_resource
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    """Initializes the database schema if tables don't exist."""
    conn = get_db_connection()
    with conn:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS sensor_raw (id INTEGER PRIMARY KEY, timestamp TEXT, sensor_id TEXT, temperature REAL, air_quality REAL, water_level REAL)")
        c.execute("CREATE TABLE IF NOT EXISTS ids_alerts (id INTEGER PRIMARY KEY, timestamp TEXT, sensor_id TEXT, feature TEXT, value REAL, alert TEXT, severity TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS encrypted_data (id INTEGER PRIMARY KEY, timestamp TEXT, encrypted TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS key_history (id INTEGER PRIMARY KEY, timestamp TEXT, key TEXT, status TEXT)")

def generate_row(i):
    """Generates a single row of sensor data, with occasional anomalies."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Base normal values
    base_temp = random.gauss(25, 2)
    base_aq = random.gauss(40, 5)
    base_wl = random.gauss(0.5, 0.1)

    # 5% chance of generating a rule-based anomaly
    if random.random() < 0.05:  
        anomaly_type = random.choice(['temp_high', 'temp_low', 'aq_spike', 'wl_low'])
        if anomaly_type == 'temp_high': base_temp += 40
        elif anomaly_type == 'temp_low': base_temp -= 20
        elif anomaly_type == 'aq_spike': base_aq += 150
        elif anomaly_type == 'wl_low': base_wl = 0.05
    
    return {
        "timestamp": ts, 
        "sensor_id": SENSOR_IDS[i % len(SENSOR_IDS)], 
        "temperature": round(base_temp, 2), 
        "air_quality": round(base_aq, 2), 
        "water_level": round(base_wl, 4)
    }

def save_to_db(query, params):
    """Generic function to save data to the database."""
    conn = get_db_connection()
    with conn:
        conn.cursor().execute(query, params)

@st.cache_data(ttl=5) # Cache data for 5 seconds
def load_df(table_name, limit=500):
    """Loads a database table into a Pandas DataFrame."""
    conn = get_db_connection()
    query = f"SELECT * FROM {table_name} ORDER BY id DESC"
    if limit:
        query += f" LIMIT {limit}"
    df = pd.read_sql_query(query, conn)
    if 'timestamp' in df.columns:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce").dt.tz_localize(None)
    return df

def run_ids_checks_on_row(row):
    """Runs simple rule-based Intrusion Detection checks."""
    alerts = []
    ts, sid = row["timestamp"], row["sensor_id"]
    try:
        if row["temperature"] > IDS_THRESHOLDS["temperature"]["max"]:
            alerts.append((ts, sid, "temperature", row["temperature"], "High temp spike", "high"))
        if row["temperature"] < IDS_THRESHOLDS["temperature"]["min"]:
            alerts.append((ts, sid, "temperature", row["temperature"], "Low temp anomaly", "medium"))
        if row["air_quality"] > IDS_THRESHOLDS["air_quality"]["max"]:
            alerts.append((ts, sid, "air_quality", row["air_quality"], "Air quality spike", "high"))
        if row["water_level"] < IDS_THRESHOLDS["water_level"]["min"]:
            alerts.append((ts, sid, "water_level", row["water_level"], "Water level low", "medium"))
    except (TypeError, KeyError):
        pass # Ignore if data is malformed
    return alerts

@st.cache_data
def convert_df_to_csv(df):
    """Converts a DataFrame to a CSV string for downloading."""
    return df.to_csv(index=False).encode('utf-8')

# ---------------------------------------------------------------------
# 4. KEY MANAGEMENT & ENCRYPTION
# ---------------------------------------------------------------------
class KeyManager:
    """Manages encryption keys and their history."""
    def __init__(self):
        if "key_history" in st.session_state:
            # Re-initialize from session state if it exists
            latest_key_info = st.session_state.key_history[0]
            self.key = latest_key_info["key"].encode()
            self.cipher = Fernet(self.key)
        else:
            # First run initialization
            self.key = Fernet.generate_key()
            self.cipher = Fernet(self.key)
            st.session_state.key_history = [{"key": self.key.decode(), "status": "active", "timestamp": time.ctime()}]
            self.save_key_history_to_db()

    def rotate_key(self):
        """Generates a new key, making it active and retiring the old one."""
        st.session_state.key_history[0]["status"] = "rotated"
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        st.session_state.key_history.insert(0, {"key": self.key.decode(), "status": "active", "timestamp": time.ctime()})
        self.save_key_history_to_db()
    
    def save_key_history_to_db(self):
        """Saves the current key history to the database."""
        conn = get_db_connection()
        with conn:
            c = conn.cursor()
            c.execute("DELETE FROM key_history")
            for rec in st.session_state.key_history:
                c.execute("INSERT INTO key_history (timestamp, key, status) VALUES (?, ?, ?)", (rec["timestamp"], rec["key"], rec["status"]))

def find_and_decrypt(token_str: str):
    """Tries all historical keys to find the one that decrypts the token."""
    token_bytes = token_str.encode()
    for key_info in st.session_state.key_history:
        try:
            f = Fernet(key_info['key'].encode())
            plaintext_bytes = f.decrypt(token_bytes)
            return {
                "status": "success", 
                "plaintext": json.loads(plaintext_bytes.decode()), 
                "key_used": key_info['key'][:8]+"...",
                "timestamp": key_info['timestamp']
            }
        except InvalidToken:
            continue
    return {"status": "failure", "message": "No valid key found in history."}


# ---------------------------------------------------------------------
# 5. STREAMLIT UI & APP LOGIC
# ---------------------------------------------------------------------

# --- Initial App Setup ---
init_db()

# Initialize session state objects
if "km" not in st.session_state:
    st.session_state.km = KeyManager()
if "live_counter" not in st.session_state:
    st.session_state.live_counter = 0
if "blockchain" not in st.session_state:
    st.session_state.blockchain = Blockchain()

# Custom CSS for a cleaner look
st.markdown("""
<style>
    .stApp { background: #f0f2f6; }
    .stButton>button { background-color: #007b70; color: white; border-radius: 8px; font-weight: 600; border: none; }
    .stButton>button:hover { background-color: #005f56; }
    [data-testid="stMetric"] { background-color: #FFFFFF; border-radius: 0.5rem; padding: 1rem; border: 1px solid #e1e1e1;}
    /* Style the radio buttons to look like tabs */
    div[role="radiogroup"] > label {
        background-color: #e8e8e8;
        padding: 8px 16px;
        border-radius: 20px;
        margin-right: 10px;
        transition: background-color 0.3s ease;
    }
    /* Style for the selected radio button */
    div[role="radiogroup"] > label:has(input:checked) {
        background-color: #007b70;
        color: white;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.title("🌍 One-Earth IoT Security Dashboard")

# --- Sidebar Controls ---
st.sidebar.header("Controls & Settings")
role = st.sidebar.selectbox("Select Role", ["Viewer", "Admin"])
admin_pass = st.sidebar.text_input("Admin Passphrase", type="password", help="Default: admin123")
is_admin = (role == "Admin" and admin_pass == ADMIN_PASSPHRASE)

if role == "Admin":
    if is_admin:
        st.sidebar.success("✅ Admin Access Granted")
    elif admin_pass:
        st.sidebar.error("Incorrect Passphrase.")
else:
    st.sidebar.info("👤 Currently in Viewer Mode.")

st.sidebar.divider()

simulate_live = st.sidebar.checkbox("Simulate live feed", value=True)
if simulate_live:
    st_autorefresh(interval=5000, key="live_refresh")
    
    # Live ingestion logic
    row = generate_row(st.session_state.live_counter)
    save_to_db("INSERT INTO sensor_raw (timestamp, sensor_id, temperature, air_quality, water_level) VALUES (?, ?, ?, ?, ?)", (row["timestamp"], row["sensor_id"], row["temperature"], row["air_quality"], row["water_level"]))
    
    for alert in run_ids_checks_on_row(row):
        save_to_db("INSERT INTO ids_alerts (timestamp, sensor_id, feature, value, alert, severity) VALUES (?, ?, ?, ?, ?, ?)", alert)
    
    token = st.session_state.km.cipher.encrypt(json.dumps(row).encode())
    save_to_db("INSERT INTO encrypted_data (timestamp, encrypted) VALUES (?, ?)", (time.ctime(), token.decode()))

    data_hash = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    st.session_state.blockchain.add_block({"sensor_id": row["sensor_id"], "data_hash": data_hash})

    st.session_state.live_counter += 1

st.sidebar.subheader("Admin Actions")
if st.sidebar.button("Generate 300 Sample Records", disabled=not is_admin):
    with st.spinner("Generating and ingesting 300 records..."):
        for i in range(300):
            row = generate_row(i)
            save_to_db("INSERT INTO sensor_raw (timestamp, sensor_id, temperature, air_quality, water_level) VALUES (?, ?, ?, ?, ?)", (row["timestamp"], row["sensor_id"], row["temperature"], row["air_quality"], row["water_level"]))
            for alert in run_ids_checks_on_row(row):
                save_to_db("INSERT INTO ids_alerts (timestamp, sensor_id, feature, value, alert, severity) VALUES (?, ?, ?, ?, ?, ?)", alert)
            token = st.session_state.km.cipher.encrypt(json.dumps(row).encode())
            save_to_db("INSERT INTO encrypted_data (timestamp, encrypted) VALUES (?, ?)", (time.ctime(), token.decode()))
            data_hash = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
            st.session_state.blockchain.add_block({"sensor_id": row["sensor_id"], "data_hash": data_hash})
    st.success("✅ Generated and processed 300 new records.")
    st.rerun()

if st.sidebar.button("🚨 Clear All Data", disabled=not is_admin, type="primary"):
    conn = get_db_connection()
    with conn:
        for table in ["sensor_raw", "ids_alerts", "encrypted_data", "key_history"]: 
            conn.cursor().execute(f"DELETE FROM {table}")
    # Reset session state objects
    st.session_state.pop("km", None)
    st.session_state.pop("blockchain", None)
    st.session_state.pop("key_history", None)
    st.success("Cleared all data and reset keys/blockchain.")
    st.rerun()

st.sidebar.divider()
st.sidebar.info("Dashboard V5 | State-Managed")


# --- Data Loading ---
raw_df = load_df("sensor_raw", limit=1000)
alerts_df = load_df("ids_alerts", limit=None)
encrypted_df = load_df("encrypted_data", limit=None)
keys_df = load_df("key_history", limit=None)

# ---------------------------------------------------------------------
# 6. DASHBOARD TABS (MODIFIED TO MAINTAIN STATE)
# ---------------------------------------------------------------------
tab_list = [
    "📈 Overview", 
    "📡 Live Feed", 
    "🛡️ IDS Alerts", 
    "🤖 AI Anomalies", 
    "🔐 Encryption", 
    "🔗 Blockchain"
]

# Use a horizontal radio button to act as stateful tabs
active_tab = st.radio(
    "Navigation", 
    tab_list, 
    horizontal=True, 
    label_visibility="collapsed",
    key="active_tab" # This key saves the state
)

# --- Overview Tab ---
if active_tab == "📈 Overview":
    st.subheader("System Status at a Glance")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Records", f"{len(raw_df):,}")
    col2.metric("High Severity Alerts", len(alerts_df[alerts_df['severity'] == 'high']))
    col3.metric("Blockchain Length", f"{len(st.session_state.blockchain.chain)} blocks")
    is_valid, msg = st.session_state.blockchain.is_chain_valid()
    validity_icon = "✅" if is_valid else "❌"
    col4.metric("Chain Integrity", validity_icon)
    st.markdown("---")
    st.subheader("Latest High Severity Alerts")
    if not alerts_df.empty:
        high_alerts = alerts_df[alerts_df['severity'] == 'high'].head()
        if not high_alerts.empty:
            st.dataframe(high_alerts.drop(columns=['timestamp_dt', 'id']), use_container_width=True)
        else:
            st.success("No high severity alerts found.")
    else:
        st.success("No alerts recorded yet.")

# --- Live Feed Tab ---
if active_tab == "📡 Live Feed":
    st.subheader("📡 Latest Sensor Feed")
    if not raw_df.empty:
        st.download_button("📥 Download Raw Data as CSV", convert_df_to_csv(raw_df), f"raw_sensor_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
        st.dataframe(raw_df.drop(columns=['timestamp_dt', 'id']).head(100), use_container_width=True, height=300)
        melted_df = raw_df.melt(id_vars=['timestamp_dt'], value_vars=['temperature', 'air_quality', 'water_level'], var_name='Metric', value_name='Value')
        chart = alt.Chart(melted_df).mark_line().encode(
            x=alt.X('timestamp_dt:T', title='Timestamp'), y=alt.Y('Value:Q', title='Sensor Value'), color='Metric:N', tooltip=['timestamp_dt', 'Metric', 'Value']
        ).interactive()
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No data yet. Enable live simulation or generate sample records.")

# --- IDS Alerts Tab ---
if active_tab == "🛡️ IDS Alerts":
    st.subheader("🛡️ Intrusion Detection System (IDS) Alerts")
    if not alerts_df.empty:
        st.download_button("📥 Download Alerts as CSV", convert_df_to_csv(alerts_df), f"ids_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
        counts = alerts_df['severity'].value_counts().reset_index()
        counts.columns = ['severity', 'count']
        donut = alt.Chart(counts).mark_arc(innerRadius=50, outerRadius=90).encode(
            theta="count:Q", color=alt.Color("severity:N", scale=alt.Scale(domain=['high', 'medium'], range=['#d62728', '#ff7f0e']), legend=alt.Legend(title="Severity")),
            tooltip=['severity', 'count']
        ).properties(title="Alerts by Severity")
        st.altair_chart(donut, use_container_width=True)
        st.dataframe(alerts_df.drop(columns=['timestamp_dt', 'id']), use_container_width=True)
    else:
        st.success("✅ No rule-based IDS alerts detected.")

# --- AI Anomalies Tab ---
if active_tab == "🤖 AI Anomalies":
    st.subheader("🤖 AI/ML Anomaly Detection (Isolation Forest)")
    contamination_level = st.slider("AI Model Sensitivity (Contamination)", 0.01, 0.25, 0.1, 0.01, help="Higher values classify more points as anomalies.")
    if len(raw_df) >= 20:
        X = raw_df[["temperature", "air_quality", "water_level"]].fillna(0).values
        model = IsolationForest(contamination=contamination_level, random_state=42).fit(X)
        raw_df['anomaly_score'] = model.decision_function(X)
        raw_df['is_anomaly'] = model.predict(X)
        anomalies_df = raw_df[raw_df['is_anomaly'] == -1]
        base = alt.Chart(raw_df).encode(x=alt.X('air_quality:Q', scale=alt.Scale(zero=False)), y=alt.Y('temperature:Q', scale=alt.Scale(zero=False)),
                                      tooltip=['timestamp', 'sensor_id', 'temperature', 'air_quality', 'water_level', 'anomaly_score']).properties(title="AI Anomaly Detection: Temperature vs. Air Quality")
        normal_points = base.transform_filter(alt.datum.is_anomaly != -1).mark_circle(opacity=0.7).encode(color=alt.value('#1f77b4'))
        anomalies = base.transform_filter(alt.datum.is_anomaly == -1).mark_circle(size=100, stroke='black', strokeWidth=2).encode(color=alt.value('#d62728'))
        st.altair_chart((normal_points + anomalies).interactive(), use_container_width=True)
        st.write(f"**Detected {len(anomalies_df)} anomalies with current sensitivity:**")
        st.download_button("📥 Download Anomalies as CSV", convert_df_to_csv(anomalies_df), f"ai_anomalies_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
        st.dataframe(anomalies_df.drop(columns=['timestamp_dt', 'is_anomaly']), use_container_width=True)
    else:
        st.info(f"Need at least 20 data points to train AI. Currently have {len(raw_df)}.")
        
# --- Encryption Tab ---
if active_tab == "🔐 Encryption":
    st.subheader("🔐 Encryption & Key Management")
    if not is_admin:
        st.warning("🔐 Key management and decryption tools are admin-only functions.")
    else:
        col1, col2 = st.columns([1, 2])
        with col1:
            st.markdown("**Key Management**")
            if st.button("Rotate Encryption Key"):
                st.session_state.km.rotate_key()
                st.success("New key generated. Old key is now 'rotated'.")
                st.rerun()
            st.markdown("**Key History**")
            if not keys_df.empty:
                st.dataframe(keys_df.drop(columns=['id', 'timestamp_dt']), use_container_width=True)
                st.download_button("📥 Download Key History", convert_df_to_csv(keys_df), f"key_history_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
        with col2:
            st.markdown("**Decryption Tool**")
            if not encrypted_df.empty:
                options = encrypted_df['id'].tolist()
                record_id_to_check = st.selectbox("Select an Encrypted Record ID to Inspect:", options)
                selected_record = encrypted_df[encrypted_df['id'] == record_id_to_check].iloc[0]
                token_str = selected_record['encrypted']
                with st.container(border=True):
                    st.markdown(f"**Ciphertext for Record #{record_id_to_check}:**")
                    st.code(token_str, language='text')
                    if st.button("Find Correct Historical Key & Decrypt"):
                        with st.spinner("Searching key history..."):
                            result = find_and_decrypt(token_str)
                            if result['status'] == 'success':
                                st.success(f"✅ Decryption Successful using key from `{result['timestamp']}` (`{result['key_used']}`)")
                                st.json(result['plaintext'])
                            else:
                                st.error(f"❌ {result['message']}")
            else:
                st.info("No encrypted records in the database yet.")

# --- Blockchain Tab ---
if active_tab == "🔗 Blockchain":
    st.subheader("🔗 Blockchain Integrity Ledger")
    chain = st.session_state.blockchain.chain
    is_valid, message = st.session_state.blockchain.is_chain_valid()
    if is_valid:
        st.success(f"✅ **Chain Integrity Verified:** The ledger is secure and untampered.")
    else:
        st.error(f"❌ **Chain Compromised:** {message}")
    chain_df = pd.DataFrame([vars(b) for b in chain])
    st.download_button("📥 Download Blockchain Ledger as CSV", convert_df_to_csv(chain_df), f"blockchain_ledger_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
    st.write(f"**Current Chain Length:** {len(chain)} blocks")
    for i, block in enumerate(reversed(chain)):
        header_text = f"**Block #{block.index}** ({block.timestamp})"
        if block.index > 0:
            prev_block_hash = chain[block.index - 1].hash
            header_text += " - ✅ Valid Link" if block.prev_hash == prev_block_hash else " - ❌ INVALID LINK"
        with st.expander(header_text):
            st.markdown("**Data:**"); st.json(block.data)
            st.markdown("**Hashes:**")
            st.text_input("Block Hash", block.hash, key=f"hash_{block.index}", disabled=True)
            st.text_input("Previous Block Hash", block.prev_hash, key=f"prev_hash_{block.index}", disabled=True)
