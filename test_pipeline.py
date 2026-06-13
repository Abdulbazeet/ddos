from feature_extractor import CICFeatureExtractor
import joblib
import numpy as np
from tensorflow.keras.models import load_model

# =========================
# LOAD MODEL + SCALER
# =========================
model = load_model("model/cnn_lstm_ddos_model.h5")
scaler = joblib.load("model/scaler.pkl")

# =========================
# EXTRACT FEATURES
# =========================
extractor = CICFeatureExtractor("capture_01.pcap")
extractor.parse_packets()
X = extractor.build_flows()

print("Raw features:")
print(X.head())

# =========================
# SCALE
# =========================
X_scaled = scaler.transform(X)

# reshape for LSTM
X_scaled = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

# =========================
# PREDICT
# =========================
pred = model.predict(X_scaled)
pred = (pred > 0.5).astype(int)

X["prediction"] = pred

print("\nRESULTS:")
print(X[["prediction"]])


#not needed