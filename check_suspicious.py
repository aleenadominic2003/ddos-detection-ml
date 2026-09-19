import pandas as pd

df = pd.read_csv("dataset/train.csv")
df.columns = df.columns.str.strip()

print("Negative values in important features:\n")

print("Fwd Header Length:")
print((df["Fwd Header Length"] < 0).sum())

print("\nmin_seg_size_forward:")
print((df["min_seg_size_forward"] < 0).sum())

print("\nInit_Win_bytes_forward:")
print((df["Init_Win_bytes_forward"] < 0).sum())