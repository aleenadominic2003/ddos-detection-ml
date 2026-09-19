import pandas as pd

train = pd.read_csv("dataset/train_clean.csv")
test = pd.read_csv("dataset/test_clean.csv")

train.columns = train.columns.str.strip()
test.columns = test.columns.str.strip()

features = [col for col in train.columns if col != "Label"]

print("Checking for conflicting duplicate labels...")

# Keep one label for each unique feature pattern
train_unique = train[features + ["Label"]].drop_duplicates()

# Find feature patterns that have more than one label in training
label_counts = train_unique.groupby(features)["Label"].nunique()

conflicting_features = label_counts[label_counts > 1].index

print("\nNumber of feature patterns with conflicting labels:",
      len(conflicting_features))

if len(conflicting_features) > 0:
    print("\nConflicting training patterns:")
    print(
        train_unique[
            train_unique.set_index(features).index.isin(conflicting_features)
        ].to_string(index=False)
    )