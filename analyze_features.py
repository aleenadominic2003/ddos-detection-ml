import pandas as pd

# Load training dataset
df = pd.read_csv("dataset/train.csv")

# Remove spaces from column names
df.columns = df.columns.str.strip()

# Select the 14 features
features = [
    "Flow Duration",
    "Fwd Packet Length Std",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd Header Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "ACK Flag Count",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    "act_data_pkt_fwd",
    "min_seg_size_forward"
]

# Display statistics
print("Feature statistics:")
print(df[features].describe().T)