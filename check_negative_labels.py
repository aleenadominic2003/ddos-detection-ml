import pandas as pd

df = pd.read_csv("dataset/train.csv")
df.columns = df.columns.str.strip()

# Convert labels to binary
df["Binary_Label"] = df["Label"].apply(
    lambda x: "BENIGN" if x == "BENIGN" else "DDoS"
)

features = [
    "Fwd Header Length",
    "min_seg_size_forward",
    "Init_Win_bytes_forward"
]

for feature in features:
    print("\n" + "=" * 50)
    print(feature)

    negative = df[df[feature] < 0]

    print("Negative values:", len(negative))

    print("\nBy class:")
    print(negative["Binary_Label"].value_counts())

    print("\nSample negative values:")
    print(negative[feature].head(10).tolist())