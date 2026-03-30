from pathlib import Path
import pandas as pd

INPUT_CSV = Path("data/interim/packets.csv")
OUTPUT_CSV = Path("data/interim/packets_clean.csv")


def main():
    if not INPUT_CSV.exists():
        print(f"Input file not found: {INPUT_CSV}")
        return

    df = pd.read_csv(INPUT_CSV)

    print(f"Original rows: {len(df)}")

    # Standardize missing values
    df["src_ip"] = df["src_ip"].fillna("UNKNOWN")
    df["dst_ip"] = df["dst_ip"].fillna("UNKNOWN")
    df["protocol"] = df["protocol"].fillna("UNKNOWN")
    df["src_port"] = df["src_port"].fillna(-1)
    df["dst_port"] = df["dst_port"].fillna(-1)
    df["tcp_flags"] = df["tcp_flags"].fillna("NONE")
    df["packet_length"] = df["packet_length"].fillna(0)

    # Convert types
    df["src_port"] = df["src_port"].astype(int)
    df["dst_port"] = df["dst_port"].astype(int)
    df["packet_length"] = df["packet_length"].astype(int)

    if "ip_version" in df.columns:
        df["ip_version"] = df["ip_version"].fillna(-1).astype(int)

    if "timestamp_raw" in df.columns:
        df["timestamp_raw"] = pd.to_numeric(df["timestamp_raw"], errors="coerce")

    # Keep packets where at least one IP is known
    df = df[(df["src_ip"] != "UNKNOWN") | (df["dst_ip"] != "UNKNOWN")]

    # Remove broadcast traffic
    if "is_broadcast" in df.columns:
        df = df[df["is_broadcast"] == False]

    # Remove mDNS traffic (very important)
    df = df[df["dst_port"] != 5353]
    df = df[df["src_port"] != 5353]

    # Keep only TCP and UDP
    df = df[df["protocol"].isin(["TCP", "UDP"])]

    # Keep multicast for now; it can be useful for IoT behavior analysis
    # If you later decide to remove it, uncomment:
    # if "is_multicast" in df.columns:
    #     df = df[df["is_multicast"] == False]

    # Remove exact duplicates
    df = df.drop_duplicates()

    print(f"Cleaned rows: {len(df)}")

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)

    print(f"Saved cleaned data to {OUTPUT_CSV}")
    print(df.head())

    print("\nProtocol counts:")
    print(df["protocol"].value_counts(dropna=False))

    if "ip_version" in df.columns:
        print("\nIP version counts:")
        print(df["ip_version"].value_counts(dropna=False))


if __name__ == "__main__":
    main()