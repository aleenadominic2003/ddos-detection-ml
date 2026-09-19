import pandas as pd

# Load test dataset
df = pd.read_csv("dataset/test.csv")

# Remove spaces from column names
df.columns = df.columns.str.strip()

print("Test dataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nOriginal labels:")
print(df["Label"].value_counts())

# Create binary label
df["Binary_Label"] = df["Label"].apply(
    lambda x: "BENIGN" if x == "BENIGN" else "DDoS"
)

print("\nBinary labels:")
print(df["Binary_Label"].value_counts())

print("\nMissing values:")
print(df.isnull().sum().sum())

print("\nDuplicate rows:")
print(df.duplicated().sum())