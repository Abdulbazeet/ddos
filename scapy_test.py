from scapy.all import rdpcap, IP
import pandas as pd
import numpy as np
import joblib
from tensorflow.keras.models import load_model

# =========================
# LOAD MODEL + SCALER
# =========================
model = load_model("model/cnn_lstm_ddos_model.h5")
scaler = joblib.load("model/scaler.pkl")

# =========================
# LOAD PCAP FILE
# =========================
pcap_file = "capture_01.pcap"  # change this

packets = rdpcap(pcap_file)

data = []

for pkt in packets:
    if IP in pkt:
        data.append({
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "len": len(pkt),
            "time": pkt.time
        })

df = pd.DataFrame(data)

# =========================
# BUILD SIMPLE FLOWS
# =========================
df["flow"] = df["src"] + "->" + df["dst"]

flows = df.groupby("flow").agg({
    "len": ["count", "mean", "sum"],
    "time": ["min", "max"]
})

flows.columns = [
    "packet_count",
    "avg_packet_size",
    "total_bytes",
    "start_time",
    "end_time"
]

flows["duration"] = flows["end_time"] - flows["start_time"]

flows = flows.drop(["start_time", "end_time"], axis=1)

# =========================
# PREPROCESS
# =========================
X = flows.replace([np.inf, -np.inf], np.nan).fillna(0)

X_scaled = scaler.transform(X)

X_scaled = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

# =========================
# PREDICT
# =========================
pred = model.predict(X_scaled)
pred = (pred > 0.5).astype(int)

flows["prediction"] = pred

print(flows)


#not needed