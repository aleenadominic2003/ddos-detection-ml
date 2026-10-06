from flask import Flask, request, jsonify, send_from_directory
import joblib
import pandas as pd
import sys
import os

app = Flask(__name__)

model = joblib.load("model/ddos_xgboost.pkl")
feature_names = joblib.load("model/feature_names.pkl")

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from demo_app.traffic_analyzer import analyze_traffic


@app.route("/")
def home():
    return send_from_directory(
        "../frontend",
        "index.html"
    )


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        input_data = pd.DataFrame([data])
        input_data = input_data[feature_names]
        prediction = model.predict(input_data)[0]
        probability = model.predict_proba(input_data)[0]
        ddos_probability = probability[1] * 100
        result = "DDoS" if prediction == 1 else "BENIGN"
        return jsonify({
            "prediction": result,
            "ddos_probability": round(ddos_probability, 4)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/traffic", methods=["GET"])
def traffic():
    try:
        traffic_data = analyze_traffic()
        return jsonify(traffic_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/detection", methods=["GET"])
def detection():
    result_file = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "demo_app",
        "results",
        "detection_result.json"
    )
)

    if not os.path.exists(result_file):
        return jsonify({
            "total_flows": 0,
            "benign_flows": 0,
            "ddos_flows": 0,
            "max_ddos_probability": 0,
            "ml_status": "NO DATA",
            "risk_level": "LOW",
            "peak_flow_rate": 0,
            "average_flow_rate": 0,
            "total_packets": 0,
            "traffic_status": "NO DATA",
            "response": "WAITING FOR ANALYSIS"
        })

    from flask import send_file
    return send_file(result_file, mimetype="application/json")


@app.route("/analyze_csv", methods=["POST"])
def analyze_csv():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        file = request.files["file"]

        if not file.filename:
            return jsonify({"error": "No file selected."}), 400

        if not file.filename.lower().endswith(".csv"):
            return jsonify({
                "error": "Only CSV files are supported for offline analysis."
            }), 400

        df = pd.read_csv(file)
        df.columns = [str(c).strip() for c in df.columns]

        missing = [c for c in feature_names if c not in df.columns]
        if missing:
            return jsonify({
                "error": (
                    "CSV is missing required model feature columns: "
                    + ", ".join(missing)
                )
            }), 400

        if df.empty:
            return jsonify({"error": "The CSV file contains no data rows."}), 400

        features = df[feature_names].copy()

        # Convert model inputs to numeric values.
        for column in feature_names:
            features[column] = pd.to_numeric(
                features[column], errors="coerce"
            )

        invalid_rows = int(features.isna().any(axis=1).sum())
        if invalid_rows:
            return jsonify({
                "error": (
                    f"The CSV contains {invalid_rows} row(s) with missing "
                    "or non-numeric model feature values."
                )
            }), 400

        predictions = model.predict(features)
        probabilities = model.predict_proba(features)[:, 1] * 100

        total_flows = int(len(features))
        ddos_flows = int((predictions == 1).sum())
        benign_flows = int((predictions == 0).sum())
        max_ddos_probability = round(float(probabilities.max()), 4)

        flow_rates = pd.to_numeric(
            features["Flow Packets/s"], errors="coerce"
        )
        peak_flow_rate = round(float(flow_rates.max()), 2)
        average_flow_rate = round(float(flow_rates.mean()), 2)

        total_packets = int(
            pd.to_numeric(
                features["Subflow Fwd Packets"], errors="coerce"
            ).sum()
        )

        if ddos_flows > 0:
            ml_status = "DDoS DETECTED"
            traffic_status = "DDoS SUSPICION"
            risk_level = "HIGH" if ddos_flows >= 5 else "MEDIUM"
            response = (
                "BLOCK / RATE LIMIT SUSPICIOUS TRAFFIC"
                if ddos_flows >= 5
                else "ALERT + MONITOR SUSPICIOUS FLOWS"
            )
        elif peak_flow_rate > 1500:
            ml_status = "BENIGN"
            traffic_status = "HIGH TRAFFIC"
            risk_level = "LOW"
            response = "CONTINUE MONITORING"
        else:
            ml_status = "BENIGN"
            traffic_status = "NORMAL TRAFFIC"
            risk_level = "LOW"
            response = "ALLOW TRAFFIC"

        return jsonify({
            "filename": file.filename,
            "total_flows": total_flows,
            "benign_flows": benign_flows,
            "ddos_flows": ddos_flows,
            "max_ddos_probability": max_ddos_probability,
            "ml_status": ml_status,
            "traffic_status": traffic_status,
            "risk_level": risk_level,
            "peak_flow_rate": peak_flow_rate,
            "average_flow_rate": average_flow_rate,
            "total_packets": total_packets,
            "response": response
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
