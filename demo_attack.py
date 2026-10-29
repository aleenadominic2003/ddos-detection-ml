
import os
import json

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




result_file = os.path.join(
    "demo_app", "results", "detection_result.json"
)
os.makedirs(os.path.dirname(result_file), exist_ok=True)

# Load the current session totals.
try:
    with open(result_file, "r", encoding="utf-8") as file:
        previous = json.load(file)
except (FileNotFoundError, json.JSONDecodeError):
    previous = {}

# Add this test's prediction to the existing totals.
current_ddos = int(ddos_flows)
current_benign = 1 - current_ddos

total_flows = int(previous.get("total_flows", 0)) + 1
benign_flows = int(previous.get("benign_flows", 0)) + current_benign
ddos_flows_total = int(previous.get("ddos_flows", 0)) + current_ddos

attack_result = {
    "total_flows": total_flows,
    "benign_flows": benign_flows,
    "ddos_flows": ddos_flows_total,
    "total_packets": int(previous.get("total_packets", 0)) + 2,
    "peak_flow_rate": max(
        float(previous.get("peak_flow_rate", 0)),
        float(peak_flow_rate)
    ),
    "average_flow_rate": float(average_flow_rate),
    "max_ddos_probability": round(
        max(
            float(previous.get("max_ddos_probability", 0)),
            float(ddos_probability)
        ),
        4
    ),
    "risk_level": "MEDIUM" if current_ddos else "LOW",
    "traffic_status": "DDoS SUSPICION" if current_ddos else "NORMAL",
    "ml_status": "DDoS DETECTED" if current_ddos else "BENIGN",
    "response": (
        "ALERT + MONITOR SUSPICIOUS FLOWS"
        if current_ddos else "MONITOR"
    )
}

with open(result_file, "w", encoding="utf-8") as file:
    json.dump(attack_result, file, indent=4)

print("\nDetection result saved. Session totals updated.")
