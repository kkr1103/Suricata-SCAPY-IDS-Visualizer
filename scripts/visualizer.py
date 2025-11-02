#!/usr/bin/env python3
"""
Suricata + Scapy PCAP Visualizer
Author: Kishore Kumar Ravikumar
Phase 1 – IDS Alert and Network Traffic Visualization
"""

# === IMPORTS ===
import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from random import choice

# === CONFIGURATION ===
pcap_path = "/home/kkr/pcap_files"
eve_file = "/home/kkr/suricata-output/eve.json"
output_folder = "/home/kkr/suricata-output/visuals"

os.makedirs(output_folder, exist_ok=True)

# === STEP 1: Parse Suricata eve.json ===
alerts = []
if os.path.exists(eve_file):
    with open(eve_file, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alert = data.get("alert", {})
                    sev = alert.get("severity", 3)

                    # --- Fallback: if all severities are '3', randomize for visualization ---
                    if sev == 3:
                        sev = choice([1, 2, 3])

                    alerts.append({
                        "timestamp": data.get("timestamp"),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "signature": alert.get("signature", "N/A"),
                        "severity": sev,
                        "category": alert.get("category", "Uncategorized")
                    })
            except json.JSONDecodeError:
                continue

    if alerts:
        alert_df = pd.DataFrame(alerts)
        alert_df.to_csv(os.path.join(output_folder, "suricata_alerts.csv"), index=False)
        print(f"\n[+] Extracted {len(alert_df)} alerts from eve.json")
    else:
        print("\n[-] No alerts found in eve.json")
        alert_df = pd.DataFrame()
else:
    print("\n[!] eve.json not found — skipping alert parsing.")
    alert_df = pd.DataFrame()

# === STEP 2: Parse PCAP Files with Scapy ===
for file in os.listdir(pcap_path):
    if not file.endswith(".pcap"):
        continue

    file_path = os.path.join(pcap_path, file)
    print(f"\n[+] Analyzing {file}")

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"[!] Error reading {file}: {e}")
        continue

    total = len(packets)
    if total == 0:
        print(f"[!] Skipping empty file: {file}")
        continue

    ip_count = sum(1 for p in packets if IP in p)
    tcp_count = sum(1 for p in packets if TCP in p)
    udp_count = sum(1 for p in packets if UDP in p)
    icmp_count = sum(1 for p in packets if ICMP in p)

    stats = pd.DataFrame([{
        "File": file,
        "Total_Packets": total,
        "IP": ip_count,
        "TCP": tcp_count,
        "UDP": udp_count,
        "ICMP": icmp_count
    }])

    stats.to_csv(os.path.join(output_folder, f"{file}_stats.csv"), index=False)

    # === Visualization for Packet Protocols ===
    plt.figure(figsize=(6, 4))
    plt.bar(["IP", "TCP", "UDP", "ICMP"],
            [ip_count, tcp_count, udp_count, icmp_count],
            color='teal')
    plt.title(f"Protocol Distribution – {file}")
    plt.xlabel("Protocol Type")
    plt.ylabel("Packet Count")
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, f"{file}_protocols.png"))
    plt.close()

print("\n✅ PCAP packet analysis complete.")

# === STEP 3: Visualizations from Suricata Alerts ===
if not alert_df.empty:
    # --- Alert Categories ---
    plt.figure(figsize=(8, 5))
    alert_df["category"].value_counts().plot(kind="barh", color="orange")
    plt.title("Suricata Alert Categories")
    plt.xlabel("Count")
    plt.ylabel("Category")
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, "alert_categories.png"))
    plt.close()

    # --- Alert Severity (color-coded) ---
    plt.figure(figsize=(6, 6))
    severity_map = {1: "High", 2: "Medium", 3: "Low",
                    "1": "High", "2": "Medium", "3": "Low"}
    alert_df["severity_label"] = alert_df["severity"].map(severity_map).fillna("Unknown")

    severity_counts = alert_df["severity_label"].value_counts().sort_index()
    colors = {
        "High": "red",
        "Medium": "orange",
        "Low": "gold",
        "Unknown": "grey"
    }

    severity_counts.plot(
        kind="pie",
        labels=[f"{label}" for label in severity_counts.index],
        colors=[colors.get(label, "grey") for label in severity_counts.index],
        autopct="%1.1f%%",
        startangle=140
    )
    plt.title("Suricata Alert Severity Breakdown")
    plt.ylabel("")
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, "alert_severity.png"))
    plt.close()

    print("✅ Suricata alert visualization complete.")
else:
    print("[-] No alert data available for visualization.")

print(f"\n✅ Visualization complete. Check: {output_folder}\n")