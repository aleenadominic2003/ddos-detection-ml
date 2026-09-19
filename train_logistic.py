import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ==========================================
# 1. Load prepared datasets
# ==========================================

print("Loading datasets...")

train = pd.read_csv("dataset/train_clean.csv")
test = pd.read_csv("dataset/test_clean.csv")

print("Training data:", train.shape)
print("Testing data:", test.shape)


# ==========================================
# 2. Separate features and labels
# ==========================================

X_train = train.drop("Label", axis=1)
y_train = train["Label"]

X_test = test.drop("Label", axis=1)
y_test = test["Label"]


# ==========================================
# 3. Scale the features
# ==========================================

print("\nScaling features...")

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# ==========================================
# 4. Create Logistic Regression model
# ==========================================

print("Training Logistic Regression model...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

model.fit(X_train_scaled, y_train)


# ==========================================
# 5. Make predictions
# ==========================================

print("Making predictions...")

y_pred = model.predict(X_test_scaled)


# ==========================================
# 6. Calculate evaluation metrics
# ==========================================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n===================================")
print("LOGISTIC REGRESSION RESULTS")
print("===================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1-Score  : {f1:.4f}")


# ==========================================
# 7. Confusion Matrix
# ==========================================

print("\nConfusion Matrix:")

cm = confusion_matrix(y_test, y_pred)

print(cm)


# ==========================================
# 8. Detailed classification report
# ==========================================

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "DDoS"]
    )
)