import pandas as pd
import joblib
from xgboost import XGBClassifier

# Load training data
train = pd.read_csv("dataset/train_clean.csv")

train.columns = train.columns.str.strip()

# Separate features and label
features = [col for col in train.columns if col != "Label"]

# Remove duplicate feature patterns
train_unique = train.drop_duplicates(subset=features)

X_train = train_unique[features]
y_train = train_unique["Label"]

print("Training final XGBoost model...")
print("Training rows:", len(X_train))
print("Features:", len(features))

# Create final model
model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)

# Train
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "model/ddos_xgboost.pkl")

# Save feature names too
joblib.dump(features, "model/feature_names.pkl")

print("\nFinal model saved successfully!")
print("Model: model/ddos_xgboost.pkl")
print("Features: model/feature_names.pkl")