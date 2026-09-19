import pandas as pd

train_df = pd.read_csv("dataset/train_clean.csv")
test_df = pd.read_csv("dataset/test_clean.csv")

train_df.columns = train_df.columns.str.strip()
test_df.columns = test_df.columns.str.strip()

print("TRAIN COLUMNS:")
print(train_df.columns.tolist())

print("\nTRAIN LABEL COUNTS:")
print(train_df["Label"].value_counts())

print("\nTEST LABEL COUNTS:")
print(test_df["Label"].value_counts())