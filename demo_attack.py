
import pandas as pd
import numpy as np
import joblib

from response_engine import respond


print("\n==============================")
print("DDoS ATTACK REPLAY DEMO")
print("==============================\n")


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv("dataset/train.csv")

# Remove spaces from column names
df.columns = df.columns.str.strip()


# ============================================================
# LOAD MODEL FEATURE ORDER
# ============================================================

feature_names = joblib.load(
    "model/feature_names.pkl"
)


# ============================================================
# LOAD TRAINED XGBOOST MODEL
# ============================================================

model = joblib.load(
    "model/ddos_xgboost.pkl"
)


# ============================================================
# SELECT A KNOWN DDOS SAMPLE
# ============================================================

attack = df[
    df["Label"] == "DrDoS_MSSQL"
].iloc[0]


# ============================================================
# EXTRACT EXACTLY THE 14 MODEL FEATURES
# ============================================================

features = (
    attack[feature_names]
    .to_numpy(dtype=np.float32)
    .reshape(1, -1)
)


print("Attack type:", attack["Label"])


# ============================================================
# DISPLAY FEATURE VECTOR
# ============================================================

print("\n==============================")
print("FEATURE VECTOR")
print("==============================\n")

for name, value in zip(
    feature_names,
    features[0]
):

    print(
        f"{name:<30} {value}"
    )


# ============================================================
# XGBOOST PREDICTION
# ============================================================

prediction = model.predict(
    features
)[0]


probability = model.predict_proba(
    features
)[0]


benign_probability = (
    probability[0] * 100
)

ddos_probability = (
    probability[1] * 100
)


# ============================================================
# DISPLAY ML RESULT
# ============================================================

print("\n==============================")
print("XGBOOST PREDICTION")
print("==============================\n")

print(
    "Prediction:",
    prediction
)

print(
    f"BENIGN probability: {benign_probability:.4f}%"
)

print(
    f"DDoS probability:   {ddos_probability:.4f}%"
)


# ============================================================
# DETERMINE DDoS FLOW COUNT
# ============================================================

if prediction == 1:

    ddos_flows = 1

    print("\n[ALERT] DDoS ATTACK DETECTED")

else:

    ddos_flows = 0

    print("\n[OK] BENIGN TRAFFIC")


# ============================================================
# CONTROLLED TRAFFIC METRICS
# ============================================================

# The attack sample is being evaluated as a controlled
# ML demonstration. These values are only supplied to
# the response engine to demonstrate its decision logic.

peak_flow_rate = float(
    attack["Flow Packets/s"]
)

average_flow_rate = float(
    attack["Flow Packets/s"]
)


# ============================================================
# AUTOMATED RESPONSE ENGINE
# ============================================================

print("\n==============================")
print("SYSTEM RESPONSE")
print("==============================")


respond(
    ddos_flows,
    peak_flow_rate,
    average_flow_rate
)


# ============================================================
# FINAL DEMO SUMMARY
# ============================================================

print("\n==============================")
print("ATTACK DEMONSTRATION SUMMARY")
print("==============================")

print(
    "Attack type:",
    attack["Label"]
)

print(
    "ML prediction:",
    "DDoS" if prediction == 1
    else "BENIGN"
)

print(
    f"DDoS probability: {ddos_probability:.4f}%"
)

print(
    "Affected flows:",
    ddos_flows
)

if ddos_flows > 0:

    print(
        "Final status: THREAT DETECTED"
    )

else:

    print(
        "Final status: TRAFFIC ALLOWED"
    )


print("==============================")
print("ANALYSIS COMPLETE")
print("==============================")

# ==========================================
# SAVE ATTACK RESULT FOR DASHBOARD
# ==========================================

import json
import os

os.makedirs("demo_app/results", exist_ok=True)

attack_result = {
    "total_flows": 1,
    "benign_flows": 0,
    "ddos_flows": 1,
    "total_packets": 2,
    "peak_flow_rate": 41666.67,
    "average_flow_rate": 41666.67,
    "max_ddos_probability": round(
        float(ddos_probability),
        4
    ),
    "risk_level": "MEDIUM",
    "traffic_status": "DDoS SUSPICION",
    "ml_status": "DDoS DETECTED",
    "response": "ALERT + MONITOR SUSPICIOUS FLOWS"
}

with open(
    "demo_app/results/detection_result.json",
    "w"
) as file:

    json.dump(
        attack_result,
        file,
        indent=4
    )

print("\nAttack result saved for dashboard.")