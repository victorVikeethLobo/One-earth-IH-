import streamlit as st
from cryptography.fernet import Fernet
import json, time, sqlite3, pandas as pd

# === Simulate Sensor Data ===
def simulate_sensor_data():
    """Simulate a new sensor reading"""
    return {
        "temperature": round(20 + 10 * st.session_state.random_factor, 1),
        "humidity": round(50 + 20 * st.session_state.random_factor, 1),
        "co2_level": round(400 + 50 * st.session_state.random_factor)
    }

# === Key Management ===
class KeyManager:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.history = [{"key": self.key.decode(), "status": "active", "timestamp": time.ctime()}]

    def rotate_key(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.history.append({"key": self.key.decode(), "status": "rotated", "timestamp": time.ctime()})

    def revoke_key(self):
        self.history[-1]["status"] = "revoked"

# === Secure Transmission ===
def secure_transmission(cipher, data: dict):
    data_str = json.dumps(data)
    encrypted = cipher.encrypt(data_str.encode())
    decrypted = cipher.decrypt(encrypted).decode()
    return encrypted, decrypted

# === SQLite DB Setup ===
def init_db():
    conn = sqlite3.connect("sensor_data.db")
    c = conn.cursor()
    # Table for encrypted sensor data
    c.execute('''CREATE TABLE IF NOT EXISTS sensor_data (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT,
                 encrypted_data TEXT
                 )''')
    # Table for key history
    c.execute('''CREATE TABLE IF NOT EXISTS key_history (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT,
                 key TEXT,
                 status TEXT
                 )''')
    conn.commit()
    conn.close()

def save_sensor_data(encrypted_data):
    conn = sqlite3.connect("sensor_data.db")
    c = conn.cursor()
    c.execute("INSERT INTO sensor_data (timestamp, encrypted_data) VALUES (?, ?)",
              (time.ctime(), encrypted_data.decode()))
    conn.commit()
    conn.close()

def save_key_history(history):
    conn = sqlite3.connect("sensor_data.db")
    c = conn.cursor()
    c.execute("DELETE FROM key_history")  # clear previous entries
    for record in history:
        c.execute("INSERT INTO key_history (timestamp, key, status) VALUES (?, ?, ?)",
                  (record["timestamp"], record["key"], record["status"]))
    conn.commit()
    conn.close()

def load_sensor_data():
    conn = sqlite3.connect("sensor_data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM sensor_data ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def load_key_history():
    conn = sqlite3.connect("sensor_data.db")
    c = conn.cursor()
    c.execute("SELECT * FROM key_history ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

# === Streamlit App Setup ===
st.set_page_config(page_title="Secure Sensor Data Demo", page_icon="🔐", layout="wide")
st.title("🔐 Secure Sensor Data (Encryption Demo)")

# Initialize DB
init_db()

# Session state setup
if "km" not in st.session_state:
    st.session_state.km = KeyManager()
if "random_factor" not in st.session_state:
    st.session_state.random_factor = 0.5  # for simulated data variation

# Simulate data
sensor_data = simulate_sensor_data()
st.subheader("📡 Current Sensor Data")
st.json(sensor_data)

# Encrypt/Decrypt
encrypted, decrypted = secure_transmission(st.session_state.km.cipher, sensor_data)

st.subheader("🔒 Encrypted Data")
st.code(encrypted.decode(), language="")

st.subheader("🔓 Decrypted Data")
st.json(json.loads(decrypted))

# Save data & key history to SQLite
save_sensor_data(encrypted)
save_key_history(st.session_state.km.history)

# Key management buttons
col1, col2 = st.columns(2)
with col1:
    if st.button("🔄 Rotate Key"):
        st.session_state.km.rotate_key()
        save_key_history(st.session_state.km.history)
with col2:
    if st.button("❌ Revoke Key"):
        st.session_state.km.revoke_key()
        save_key_history(st.session_state.km.history)

# Show key history
st.subheader("🔑 Key Status History")
key_hist = load_key_history()
st.dataframe(pd.DataFrame(key_hist, columns=["ID", "Timestamp", "Key", "Status"]))

# Show past encrypted data
st.subheader("🗄️ Stored Encrypted Data")
rows = load_sensor_data()
st.dataframe(pd.DataFrame(rows, columns=["ID", "Timestamp", "Encrypted Data"]))

# Decrypt past data
st.subheader("🗂️ Decrypt Historical Data")
selected_id = st.number_input("Enter record ID to decrypt", min_value=1, step=1)
if st.button("Decrypt Selected Record"):
    match = [r for r in rows if r[0] == selected_id]
    if match:
        encrypted_data = match[0][2].encode()
        try:
            decrypted_text = st.session_state.km.cipher.decrypt(encrypted_data).decode()
            st.json(json.loads(decrypted_text))
        except:
            st.error("Decryption failed. Possibly a key mismatch.")
    else:
        st.warning("Record ID not found.")

# Export feature
st.subheader("💾 Export Data")
if st.button("Export Sensor Data to CSV"):
    df = pd.DataFrame(rows, columns=["ID", "Timestamp", "Encrypted Data"])
    df.to_csv("sensor_data_export.csv", index=False)
    st.success("Exported as sensor_data_export.csv")
