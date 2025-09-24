from cryptography.fernet import Fernet
import json
import time

# === Step 1: Simulate Sensor Data ===
def simulate_sensor_data():
    return {
        "temperature": 27.5,
        "humidity": 68,
        "co2_level": 412
    }

# === Step 2: Key Management ===
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

# === Step 3: Encrypt / Decrypt Data ===
def secure_transmission(cipher, data: dict):
    # Convert dict to JSON string for encryption
    data_str = json.dumps(data)
    encrypted = cipher.encrypt(data_str.encode())
    decrypted = cipher.decrypt(encrypted).decode()
    return encrypted, decrypted

# === Demo ===
if __name__ == "__main__":
    # Simulate sensor data
    sensor_data = simulate_sensor_data()

    # Key manager
    km = KeyManager()

    # Secure transmission (Sensor -> Gateway)
    encrypted, decrypted = secure_transmission(km.cipher, sensor_data)

    # Rotate the key
    km.rotate_key()

    # Prepare output
    output = {
        "sensor_data": sensor_data,
        "encrypted": encrypted.decode(),
        "decrypted": json.loads(decrypted),
        "key_status_history": km.history
    }

    # Print JSON output
    print(json.dumps(output, indent=4))
