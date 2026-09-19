import pandas as pd

# ==============================
# 1. Load datasets
# ==============================

train = pd.read_csv("dataset/train.csv")
test = pd.read_csv("dataset/test.csv")

# Remove extra spaces from column names
train.columns = train.columns.str.strip()
test.columns = test.columns.str.strip()


# ==============================
# 2. Convert labels
# ==============================

# BENIGN = 0
# All attack types = 1 (DDoS)

train["Label"] = train["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

test["Label"] = test["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)


# ==============================
# 3. Separate features and labels
# ==============================

X_train = train.drop("Label", axis=1)
y_train = train["Label"]

X_test = test.drop("Label", axis=1)
y_test = test["Label"]


# ==============================
# 4. Check the data
# ==============================

print("X_train shape:", X_train.shape)
print("y_train shape:", y_train.shape)

print("X_test shape:", X_test.shape)
print("y_test shape:", y_test.shape)

print("\nTraining labels:")
print(y_train.value_counts())

print("\nTesting labels:")
print(y_test.value_counts())

print("\nAll feature columns:")
print(X_train.columns.tolist())

print("\nData types:")
print(X_train.dtypes)


# ==============================
# 5. Save prepared datasets
# ==============================

train_clean = X_train.copy()
train_clean["Label"] = y_train

test_clean = X_test.copy()
test_clean["Label"] = y_test

train_clean.to_csv("dataset/train_clean.csv", index=False)
test_clean.to_csv("dataset/test_clean.csv", index=False)

print("\nPrepared datasets saved successfully!")