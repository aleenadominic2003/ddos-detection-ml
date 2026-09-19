import pandas as pd

# Load dataset
df = pd.read_csv("dataset/train.csv")

# Remove spaces from column names
df.columns = df.columns.str.strip()

# Create binary label
df["Binary_Label"] = df["Label"].apply(
    lambda x: "BENIGN" if x == "BENIGN" else "DDoS"
)

# Find duplicate rows
duplicates = df[df.duplicated(keep=False)]

print("Total rows:", len(df))
print("Duplicate rows:", len(duplicates))

print("\nDuplicate rows by binary class:")
print(duplicates["Binary_Label"].value_counts())

print("\nOriginal labels among duplicate rows:")
print(duplicates["Label"].value_counts())