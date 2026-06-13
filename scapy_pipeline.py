from scapy.all import rdpcap, IP, TCP
import pandas as pd

pcap_file = "sample.pcap"  # change this

packets = rdpcap(pcap_file)

data = []

for pkt in packets:
    if IP in pkt:
        try:
            data.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "length": len(pkt),
                "time": pkt.time
            })
        except:
            pass

df = pd.DataFrame(data)

print(df.head())

df["flow_id"] = df["src_ip"] + "→" + df["dst_ip"]

flow_df = df.groupby("flow_id").agg({
    "length": ["count", "mean", "sum"],
    "time": ["min", "max"]
})

flow_df.columns = [
    "packet_count",
    "avg_packet_size",
    "total_bytes",
    "start_time",
    "end_time"
]

flow_df["flow_duration"] = flow_df["end_time"] - flow_df["start_time"]

flow_df = flow_df.drop(["start_time", "end_time"], axis=1)

print(flow_df.head())

#not needed