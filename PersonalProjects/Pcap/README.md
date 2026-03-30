IoT Network Traffic ML Analyzer
Overview

This project analyzes real-world IoT network traffic captured using Wireshark and transforms raw PCAP data into structured datasets for machine learning and behavioral analysis.

The goal is to identify device communication patterns and detect anomalous network behavior using statistical features and unsupervised learning.

Key Features
Extracted packet-level data from PCAP files using Scapy
Converted raw 802.11 WiFi captures into IP-level datasets
Cleaned and standardized noisy real-world network traffic
Engineered behavioral features such as:
packet size distributions
communication frequency
time between packets
Built flow-based datasets to represent communication patterns
Applied anomaly detection using Isolation Forest
Generated device-level behavioral profiles
Technologies Used
Python
pandas
NumPy
Scapy
scikit-learn
Wireshark
Jupyter Notebook
Project Pipeline
Capture network traffic using Wireshark
Export decrypted IP packets from 802.11 capture
Extract packet-level data using Scapy
Clean and standardize dataset
Engineer flow-based features
Apply anomaly detection and behavioral analysis
Example Insights
IoT devices exhibit consistent and periodic communication patterns even when idle
Multicast DNS traffic dominates raw IoT network captures and must be filtered
Devices can be distinguished based on packet size, timing, and communication endpoints
Running the Project
pip install -r requirements.txt
python src/extract_packets.py
python src/clean_packets.py

Open notebooks for analysis:

notebooks/01_data_validation.ipynb
notebooks/02_feature_engineering.ipynb
Future Improvements
Device labeling and classification models
Real-time traffic analysis pipeline
Dashboard for visualizing device behavior
Integration with LLM-based analysis tools