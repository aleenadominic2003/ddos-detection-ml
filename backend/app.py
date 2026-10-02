from flask import Flask, request, jsonify, send_from_directory
import joblib
import pandas as pd
import sys
import os
import json

app = Flask(__name__)

# -------------------------------------------------
# Load ML model
# -------------------------------------------------

model = joblib.load("model/ddos_xgboost.pkl")

feature_names = joblib.load("model/feature_names.pkl")


# -------------------------------------------------
# Import traffic analyzer
# -------------------------------------------------

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from demo_app.traffic_analyzer import analyze_traffic


# -------------------------------------------------
# Home
# -------------------------------------------------

@app.route("/")
def home():
    return send_from_directory(
        "../frontend",
        "index.html"
    )


# -------------------------------------------------
# ML Prediction API
# -------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json()

        input_data = pd.DataFrame([data])

        input_data = input_data[feature_names]

        prediction = model.predict(input_data)[0]

        probability = model.predict_proba(input_data)[0]

        ddos_probability = probability[1] * 100

        if prediction == 1:
            result = "DDoS"
        else:
            result = "BENIGN"

        return jsonify({

            "prediction": result,

            "ddos_probability":
                round(ddos_probability, 4)

        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 400


# -------------------------------------------------
# Traffic Statistics API
# -------------------------------------------------

@app.route("/traffic", methods=["GET"])
def traffic():

    try:

        traffic_data = analyze_traffic()

        return jsonify(traffic_data)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500

@app.route("/detection", methods=["GET"])
def detection():
    try:
        result_file = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "demo_app",
                "results",
                "detection_result.json"
            )
        )

        with open(result_file, "r") as file:
            data = json.load(file)

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# -------------------------------------------------
# Run Flask
# -------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )