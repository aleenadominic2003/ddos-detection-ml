import pandas as pd

print("Loading datasets...")

train = pd.read_csv("dataset/train_clean.csv")
test = pd.read_csv("dataset/test_clean.csv")

print("Train rows:", len(train))
print("Test rows:", len(test))

# Remove Label because we want to compare
# the actual traffic features
X_train = train.drop("Label", axis=1)
X_test = test.drop("Label", axis=1)

# Create a unique representation of each row
train_rows = set(map(tuple, X_train.values))
test_rows = set(map(tuple, X_test.values))

# Find rows appearing in both datasets
overlap = train_rows.intersection(test_rows)

print("\nUnique train rows:", len(train_rows))
print("Unique test rows:", len(test_rows))
print("Rows appearing in BOTH train and test:", len(overlap))

print("\nPercentage of unique test rows also found in train:")

if len(test_rows) > 0:
    percentage = (len(overlap) / len(test_rows)) * 100
    print(f"{percentage:.2f}%")