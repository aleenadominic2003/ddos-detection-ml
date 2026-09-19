import pandas as pd

from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Load data
train = pd.read_csv("dataset/train_clean.csv")
test = pd.read_csv("dataset/test_clean.csv")

train.columns = train.columns.str.strip()
test.columns = test.columns.str.strip()

# Separate features and label
features = [col for col in train.columns if col != "Label"]

X_train = train[features]
y_train = train["Label"]

X_test = test[features]
y_test = test["Label"]

print("Original training rows:", len(train))
print("Original testing rows :", len(test))

# Remove duplicate feature patterns from training data
train_unique = train.drop_duplicates(subset=features)

X_train_unique = train_unique[features]
y_train_unique = train_unique["Label"]

print("\nTraining rows after removing duplicate feature patterns:",
      len(train_unique))

# Find test rows whose feature pattern was NOT seen in training
train_feature_set = set(map(tuple, X_train_unique.values))

unseen_mask = [
    tuple(row) not in train_feature_set
    for row in X_test.values
]

X_test_unseen = X_test[unseen_mask]
y_test_unseen = y_test[unseen_mask]

print("Unseen test rows:", len(X_test_unseen))

# Train XGBoost
print("\nTraining XGBoost on unique training patterns...")

model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)

model.fit(X_train_unique, y_train_unique)

# Predict only unseen test patterns
y_pred = model.predict(X_test_unseen)

# Evaluation
accuracy = accuracy_score(y_test_unseen, y_pred)
precision = precision_score(y_test_unseen, y_pred)
recall = recall_score(y_test_unseen, y_pred)
f1 = f1_score(y_test_unseen, y_pred)

print("\n===== STRICT XGBOOST RESULTS =====")
print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1-Score  : {f1:.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test_unseen, y_pred, labels=[0, 1]))

print("\nClassification Report:")
print(classification_report(
    y_test_unseen,
    y_pred,
    labels=[0, 1],
    target_names=["BENIGN", "DDoS"]
))