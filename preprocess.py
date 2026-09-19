import pandas as pd

# Load datasets
train = pd.read_csv("dataset/train.csv")
test = pd.read_csv("dataset/test.csv")

# Remove spaces from column names
train.columns = train.columns.str.strip()
test.columns = test.columns.str.strip()

# Convert labels into binary classification
# BENIGN = 0
# Everything else = 1 (DDoS)

train["Label"] = train["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

test["Label"] = test["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

print("Training dataset shape:", train.shape)
print("Testing dataset shape:", test.shape)

print("\nTraining labels:")
print(train["Label"].value_counts())

print("\nTesting labels:")
print(test["Label"].value_counts())

# Separate features and labels
X_train = train.drop("Label", axis=1)
y_train = train["Label"]

X_test = test.drop("Label", axis=1)
y_test = test["Label"]

print("\nNumber of training features:", X_train.shape[1])
print("Number of testing features:", X_test.shape[1])

print("\nFeature names:")
print(X_train.columns.tolist())