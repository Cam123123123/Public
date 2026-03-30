# IoT Network Traffic Behavioral Analyzer

## Overview
This project analyzes IoT network traffic captured from a home environment using Wireshark PCAP data. The goal is to clean and structure noisy packet data, extract behavior-based features, and explore whether IoT devices can be distinguished by their communication patterns.

## Project Goal
The main objective is to transform raw network traffic into a reliable dataset for analysis and potential machine learning tasks such as:
- device type classification
- traffic behavior classification
- behavioral fingerprinting of IoT devices

## Tech Stack
- Python
- Scapy
- pandas
- NumPy
- scikit-learn
- Jupyter
- Matplotlib
- Wireshark

## Project Structure
```text
project-name/
  src/
  notebooks/
  data/
  models/
  tests/
  README.md
  requirements.txt