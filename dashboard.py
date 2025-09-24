import streamlit as st
import pandas as pd
import hashlib
import json
from datetime import datetime

# -------------------------
# Load Your Simulated Data
# -------------------------
st.title("🌍 Blockchain + Data Integrity + Dashboard")

try:
    sensor_data = pd.read_csv("sensor_data.csv")
except FileNotFoundError:
    st.error("sensor_data.csv not found. Run simulator.py first.")
    st.stop()

st.subheader("1️⃣ Sensor Data (from simulator.py)")
st.dataframe(sensor_data.head(15))   # show first 15 rows

# -------------------------
# Compute Hashes
# -------------------------
def compute_hash(data_str):
    return hashlib.sha256(data_str.encode()).hexdigest()

sensor_data["hash"] = sensor_data.apply(
    lambda row: compute_hash(
        f"{row['sensor_id']}_{row['temperature']}_{row['air_quality']}_{row['water_level']}_{row['timestamp']}"
    ),
    axis=1
)

st.subheader("2️⃣ Data with SHA-256 Hash")
st.dataframe(sensor_data[["sensor_id", "temperature", "air_quality", "water_level", "hash"]].head(15))

# -------------------------
# Provenance Tracking
# -------------------------
provenance_records = []
for _, row in sensor_data.iterrows():
    prov = {
        "sensor_id": row["sensor_id"],
        "timestamp": row["timestamp"],
        "processed_by": "Node_1",
        "hash": row["hash"]
    }
    provenance_records.append(prov)

st.subheader("3️⃣ Provenance Metadata (Example)")
st.json(provenance_records[0])  # show one example record
# -------------------------
# Blockchain Simulation + IPFS
# -------------------------
class Block:
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()
        self.ipfs_link = self.generate_ipfs_link()

    def calculate_hash(self):
        return hashlib.sha256(
            (str(self.index) + str(self.timestamp) + json.dumps(self.data) + str(self.prev_hash)).encode()
        ).hexdigest()

    def generate_ipfs_link(self):
        # Fake IPFS hash like "ipfs://Qm..." (46 chars)
        rand_hash = ''.join(random.choices(string.ascii_letters + string.digits, k=46))
        return f"ipfs://{rand_hash}"

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, str(datetime.now()), "Genesis Block", "0")

    def add_block(self, data):
        prev_block = self.chain[-1]
        new_block = Block(len(self.chain), str(datetime.now()), data, prev_block.hash)
        self.chain.append(new_block)

bc = Blockchain()
for prov in provenance_records[:10]:  # add first 10 records
    bc.add_block(prov)

st.subheader("4️⃣ Blockchain + IPFS Ledger (Simulated)")
for block in bc.chain:
    st.json({
        "index": block.index,
        "timestamp": block.timestamp,
        "data": block.data,
        "hash": block.hash[:12] + "...",
        "prev_hash": block.prev_hash[:12] + "...",
        "ipfs_link": block.ipfs_link
    })

# -------------------------
# Dashboard Summary
# -------------------------
st.subheader("5️⃣ Dashboard Summary")
st.success("✅ Data → Hash → Provenance → Blockchain workflow complete!")
