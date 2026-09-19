import pandas as pd

df = pd.read_csv("dataset/train.csv")
df.columns = df.columns.str.strip()

# Convert to binary labels
df["Binary_Label"] = df["Label"].apply(
    lambda x: "BENIGN" if x == "BENIGN" else "DDoS"
)

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

# Calculate mean for each class
comparison = df.groupby("Binary_Label")[features].mean().T

print("Mean feature values by class:")
print(comparison)