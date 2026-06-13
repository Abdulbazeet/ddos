from scapy.all import rdpcap, IP, TCP
import pandas as pd
import numpy as np


class CICFeatureExtractor:

    def __init__(self, pcap_file):
        self.packets = rdpcap(pcap_file)
        self.data = []

    def parse_packets(self):
        for pkt in self.packets:
            if IP in pkt:
                proto = pkt[IP].proto

                tcp_flags = 0
                syn_flag = 0
                ack_flag = 0

                if TCP in pkt:
                    flags = pkt[TCP].flags
                    syn_flag = int(flags == "S")
                    ack_flag = int(flags == "A")
                    tcp_flags = int(flags)

                self.data.append({
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "len": len(pkt),
                    "time": float(pkt.time),
                    "proto": proto,
                    "syn": syn_flag,
                    "ack": ack_flag
                })

        self.df = pd.DataFrame(self.data)

    def build_flows(self):

        self.df["flow"] = self.df["src"] + "->" + self.df["dst"]

        grouped = self.df.groupby("flow")

        features = pd.DataFrame()

        # =========================
        # BASIC FLOW FEATURES
        # =========================
        features["packet_count"] = grouped.size()
        features["total_bytes"] = grouped["len"].sum()
        features["avg_packet_size"] = grouped["len"].mean()

        # =========================
        # TIME FEATURES
        # =========================
        features["start_time"] = grouped["time"].min()
        features["end_time"] = grouped["time"].max()
        features["duration"] = features["end_time"] - features["start_time"]

        # =========================
        # RATE FEATURES
        # =========================
        features["bytes_per_sec"] = features["total_bytes"] / (features["duration"] + 0.001)
        features["packets_per_sec"] = features["packet_count"] / (features["duration"] + 0.001)

        # =========================
        # FLAG FEATURES
        # =========================
        features["syn_count"] = grouped["syn"].sum()
        features["ack_count"] = grouped["ack"].sum()

        # =========================
        # CLEAN
        # =========================
        features = features.replace([np.inf, -np.inf], np.nan).fillna(0)

        return features