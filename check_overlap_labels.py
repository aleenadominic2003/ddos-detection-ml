import pandas as pd

print("Loading datasets...")

train = pd.read_csv("dataset/train_clean.csv")
test = pd.read_csv("dataset/test_clean.csv")

# Create a dictionary:
# traffic features → training label
train_features = train.drop("Label", axis=1)

train_lookup = {}

for i in range(len(train)):
    row = tuple(train_features.iloc[i])
    train_lookup[row] = train.iloc[i]["Label"]

# Check overlapping rows
test_features = test.drop("Label", axis=1)

overlap_count = 0
conflicting_count = 0

for i in range(len(test)):
    row = tuple(test_features.iloc[i])

    if row in train_lookup:
        overlap_count += 1

        train_label = train_lookup[row]
        test_label = test.iloc[i]["Label"]

        if train_label != test_label:
            conflicting_count += 1

print("\nTotal test rows:", len(test))
print("Overlapping test rows:", overlap_count)
print("Conflicting labels:", conflicting_count)

if overlap_count > 0:
    consistency = (
        (overlap_count - conflicting_count)
        / overlap_count
    ) * 100

    print(f"Label consistency: {consistency:.2f}%")