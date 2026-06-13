



import os
import subprocess
import pandas as pd
import numpy as np
import tempfile
import joblib

from tensorflow.keras.models import load_model

# =========================
# LOAD MODEL + SCALER
# =========================

# MODEL_PATH = "model/cnn_lstm_ddos_model.h5"
# SCALER_PATH = "model/scaler.pkl"



PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(PROJECT_ROOT, "model/cnn_lstm_ddos_model.h5")
SCALER_PATH = os.path.join(PROJECT_ROOT, "model/scaler.pkl")

model = load_model(MODEL_PATH)

scaler = joblib.load(SCALER_PATH)

# =========================
# FEATURE MAPPING
# =========================

feature_mapping = {
    "flow_duration": " Flow Duration",
    "tot_fwd_pkts": " Total Fwd Packets",
    "tot_bwd_pkts": " Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": " Total Length of Bwd Packets",
    "fwd_pkt_len_max": " Fwd Packet Length Max",
    "fwd_pkt_len_min": " Fwd Packet Length Min",
    "fwd_pkt_len_mean": " Fwd Packet Length Mean",
    "fwd_pkt_len_std": " Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": " Bwd Packet Length Min",
    "bwd_pkt_len_mean": " Bwd Packet Length Mean",
    "bwd_pkt_len_std": " Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": " Flow Packets/s",
    "flow_iat_mean": " Flow IAT Mean",
    "flow_iat_std": " Flow IAT Std",
    "flow_iat_max": " Flow IAT Max",
    "flow_iat_min": " Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": " Fwd IAT Mean",
    "fwd_iat_std": " Fwd IAT Std",
    "fwd_iat_max": " Fwd IAT Max",
    "fwd_iat_min": " Fwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "fwd_header_len": " Fwd Header Length",
    "bwd_header_len": " Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": " Bwd Packets/s",
    "pkt_len_min": " Min Packet Length",
    "pkt_len_max": " Max Packet Length",
    "pkt_len_mean": " Packet Length Mean",
    "pkt_len_std": " Packet Length Std",
    "pkt_len_var": " Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": " SYN Flag Count",
    "rst_flag_cnt": " RST Flag Count",
    "psh_flag_cnt": " PSH Flag Count",
    "ack_flag_cnt": " ACK Flag Count",
    "urg_flag_cnt": " URG Flag Count",
    "down_up_ratio": " Down/Up Ratio",
    "pkt_size_avg": " Average Packet Size",
    "fwd_seg_size_avg": " Avg Fwd Segment Size",
    "bwd_seg_size_avg": " Avg Bwd Segment Size",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": " Subflow Fwd Bytes",
    "subflow_bwd_pkts": " Subflow Bwd Packets",
    "subflow_bwd_byts": " Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": " Init_Win_bytes_backward",
    "fwd_act_data_pkts": " act_data_pkt_fwd",
    "active_mean": "Active Mean",
    "active_std": " Active Std",
    "active_max": " Active Max",
    "active_min": " Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": " Idle Std",
    "idle_max": " Idle Max",
    "idle_min": " Idle Min"
}

# =========================
# MAIN FUNCTION
# =========================

def analyze_pcap(pcap_file):

    temp_csv = tempfile.NamedTemporaryFile(
        suffix=".csv",
        delete=False
    ).name

    # =========================
    # RUN CICFLOWMETER
    # =========================

    command = [
        "cicflowmeter",
        "-f",
        pcap_file,
        "-c",
        temp_csv
    ]

    subprocess.run(command, check=True)

    # =========================
    # LOAD GENERATED CSV
    # =========================

    df = pd.read_csv(temp_csv)

    if df.empty:
        return {
            "error": "No flows extracted from PCAP."
        }

    # =========================
    # RENAME FEATURES
    # =========================

    df = df.rename(columns=feature_mapping)

    # =========================
    # KEEP REQUIRED FEATURES
    # =========================

    required_features = scaler.feature_names_in_

    for feature in required_features:
        if feature not in df.columns:
            df[feature] = 0

    X = df[required_features]

    # =========================
    # CLEAN INVALID VALUES
    # =========================

    X.replace([np.inf, -np.inf], 0, inplace=True)

    X.fillna(0, inplace=True)

    # =========================
    # SCALE
    # =========================

    X_scaled = scaler.transform(X)

    # =========================
    # RESHAPE
    # =========================

    X_scaled = X_scaled.reshape(
        X_scaled.shape[0],
        X_scaled.shape[1],
        1
    )

    # =========================
    # PREDICT
    # =========================

    predictions = model.predict(X_scaled)

    predicted_labels = (
        predictions > 0.5
    ).astype(int)

    attack_count = int(np.sum(predicted_labels))

    normal_count = int(
        len(predicted_labels) - attack_count
    )

    attack_ratio = (
        attack_count / len(predicted_labels)
    ) * 100

    # =========================
    # VERDICT
    # =========================

    if attack_ratio > 70:
        verdict = "LIKELY DDoS TRAFFIC"

    elif attack_ratio > 30:
        verdict = "SUSPICIOUS TRAFFIC"

    else:
        verdict = "MOSTLY NORMAL TRAFFIC"

    # =========================
    # CLEAN TEMP FILE
    # =========================

    os.remove(temp_csv)

    risk_score = min(
        100,
        round(attack_ratio + (attack_count / max(len(predicted_labels), 1)) * 10, 2)
    )

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if attack_ratio > 70:
        explanation = "High concentration of attack-like flows detected. Likely DDoS behavior."
    elif attack_ratio > 30:
        explanation = "Mixed traffic with suspicious patterns detected."
    else:
        explanation = "Traffic appears mostly normal."

    return {
        # CORE RESULT
        "prediction": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "verdict": verdict,

        # STATS (same as before but structured)
        "stats": {
            "total_flows": len(predicted_labels),
            "attack_flows": attack_count,
            "normal_flows": normal_count,
            "attack_ratio": round(attack_ratio, 2)
        },

        # UI FRIENDLY DATA
        "visuals": {
            "attack_ratio": round(attack_ratio, 2),
            "normal_ratio": round(100 - attack_ratio, 2)
        },

        # HUMAN EXPLANATION
        "explanation": explanation
    }

    # return {
    #     "total_flows": len(predicted_labels),
    #     "attack_flows": attack_count,
    #     "normal_flows": normal_count,
    #     "attack_ratio": round(attack_ratio, 2),
    #     "verdict": verdict
    # }
    

# =========================
# TEST
# =========================

if __name__ == "__main__":

    result = analyze_pcap("capture_01.pcap")

    print("\n========== ANALYSIS ==========")

    print(result)