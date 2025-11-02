# Suricata-SCAPY-IDS-Visualizer
Automated Suricata + Scapy Intrusion Detection Visualizer — parses PCAP traffic, analyzes IDS alerts, and generates interactive network-security visual reports.

1. Project Overview
This project demonstrates how Suricata IDS and Scapy can be used with Python to detect and visualize malicious network activity.
It replicates a simplified Security Operations Center (SOC) workflow — analyzing packet captures (.pcap files), detecting alerts, and presenting them through visual summaries.

2. Objectives
. Detect and classify suspicious traffic from PCAP files
. Categorize alerts by severity (1, 2, 3) and type (Trojan, Reconnaissance, etc.)
. Summarize traffic patterns by protocol (IP, TCP, UDP, ICMP)
. Automate visualization and reporting of Suricata results

3. Tools and Technologies
. Suricata: Intrusion Detection System used to analyze packet captures and generate alerts.
. Python 3.10+, Pandas, Matplotlib: Used for data parsing, processing, and visualization.
. Scapy: Reads and analyzes PCAP files to extract protocol and packet statistics.
. Ubuntu Linux: Secure testing environment for IDS configuration and analysis.
. PCAP Dataset: Contains both normal and malicious traffic samples.

4. Setup Instructions
(i) Suricata Installation
     sudo apt update  
     sudo apt install suricata -y
(ii) Verify installation:
      suricata --version
(iii) Python and Library Installation
      sudo apt install python3-pip -y  
      pip install pandas matplotlib scapy
(Alternatively: pip install -r requirements.txt)
(iv) Updating Suricata Rules
      sudo suricata-update  
      sudo systemctl restart suricata

5. How the Project Works
(i) Suricata Detection
. Suricata runs in offline mode to scan .pcap files.
. It generates an output log file named eve.json containing detected alerts.
. Each alert includes details such as source and destination IP, timestamp, category, and severity level.
(ii) Scapy Analysis
. Scapy reads every .pcap file and counts the total packets and the number of IP, TCP, UDP, and ICMP packets.
. This provides a simple overview of the network’s traffic composition.
(iii) Python Visualization
. The visualizer.py script reads Suricata’s eve.json and the PCAP files.
. It generates visual reports, including:
    Pie charts showing alert severity levels.
    Bar charts for alert categories.
    Bar charts for protocol distribution.
. CSV summaries are also created for further analysis.

6. Outputs Produced
. alert_severity.png: Pie chart showing proportions of severity 1, 2, and 3 alerts.
. alert_categories.png: Bar chart displaying types of detected alerts.
. protocols.png: Bar chart showing network protocol distribution (IP, TCP, UDP, ICMP).
. suricata_alerts.csv: Table of all detected alerts.
. pcap_stats.csv: Packet statistics for each PCAP file.

7. Data Interpretation
. Severity 1 (High): Critical or confirmed malicious activity.
. Severity 2 (Medium): Suspicious but not confirmed as malicious.
. Severity 3 (Low): Informational or benign activity.
. Protocol Analysis: Shows which protocols dominate the traffic.
. CSV and Charts: Provide structured and visual summaries for deeper analysis.

8. Educational Value
. This project demonstrates practical cybersecurity concepts:
  IDS configuration and rule management
  Packet-level threat detection
  Automated reporting and visualization
  Realistic SOC-style alert analysis
It is ideal for cybersecurity portfolios.

9. Conclusion
. The Suricata and Scapy IDS Visualizer integrates detection, analysis, and visualization into one automated workflow.
. It converts raw network captures into meaningful visual reports, helping analysts understand and respond to threats effectively.

© 2025 Kishore Kumar Ravikumar. All rights reserved.
