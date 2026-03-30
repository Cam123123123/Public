from pathlib import Path
import pandas as pd
from scapy.all import PcapReader, IP, TCP, UDP, Dot11

INPUT_PCAP = Path("data/raw/stripIP_3-30-26.pcapng")
OUTPUT_CSV = Path("data/interim/packets.csv")


def format_timestamp(raw_time):
    if raw_time is None:
        return None

    ts_str = str(raw_time)
    if "." in ts_str:
        before, after = ts_str.split(".", 1)
        return f"{before[-2:]}.{after[:4]}"
    return ts_str[-2:]


def extract_packet_row(packet):
    row = {
        "timestamp": format_timestamp(getattr(packet, "time", None)),
        "src_ip": None,
        "dst_ip": None,
        "src_mac": None,
        "dst_mac": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "packet_length": len(packet),
        "tcp_flags": None,
        "is_broadcast": False,
        "is_multicast": False,
        "highest_layer": packet.lastlayer().name if hasattr(packet, "lastlayer") else None,
    }

    if Dot11 in packet:
        row["src_mac"] = getattr(packet[Dot11], "addr2", None)
        row["dst_mac"] = getattr(packet[Dot11], "addr1", None)

    if IP in packet:
        row["src_ip"] = packet[IP].src
        row["dst_ip"] = packet[IP].dst

        if row["dst_ip"] == "255.255.255.255":
            row["is_broadcast"] = True

        try:
            first_octet = int(row["dst_ip"].split(".")[0])
            if 224 <= first_octet <= 239:
                row["is_multicast"] = True
        except Exception:
            pass

    if TCP in packet:
        row["protocol"] = "TCP"
        row["src_port"] = packet[TCP].sport
        row["dst_port"] = packet[TCP].dport
        row["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        row["protocol"] = "UDP"
        row["src_port"] = packet[UDP].sport
        row["dst_port"] = packet[UDP].dport

    return row


def main():
    if not INPUT_PCAP.exists():
        print(f"PCAP not found: {INPUT_PCAP}")
        return

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    processed = 0
    kept = 0

    print(f"Reading packets from {INPUT_PCAP} ...")

    with PcapReader(str(INPUT_PCAP)) as pcap_reader:
        for packet in pcap_reader:
            processed += 1

            try:
                row = extract_packet_row(packet)
                rows.append(row)
                kept += 1
            except Exception:
                continue

            if processed % 10000 == 0:
                print(f"Processed {processed} packets...")

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"Finished. Processed {processed} packets.")
    print(f"Saved {kept} rows to {OUTPUT_CSV}")
    print(df.head())


if __name__ == "__main__":
    main()