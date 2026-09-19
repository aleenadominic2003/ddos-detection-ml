import pandas as pd
import numpy as np

# Load dataset
df = pd.read_csv("dataset/train.csv")

# Remove spaces from column names
df.columns = df.columns.str.strip()

# Create binary label
df["Binary_Label"] = df["Label"].apply(
    lambda x: "BENIGN" if x == "BENIGN" else "DDoS"
)

print("========== DATASET INFO ==========")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])

print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())

print("\n========== INFINITE VALUES ==========")

# Select only numerical columns
numeric_df = df.select_dtypes(include=np.number)

print(np.isinf(numeric_df).sum())

print("\n========== DUPLICATE ROWS ==========")
print("Duplicates:", df.duplicated().sum())

print("\n========== BINARY LABEL COUNT ==========")
print(df["Binary_Label"].value_counts())