from flask import Flask, request, jsonify
import joblib
import pandas as pd

app = Flask(__name__)

# Load the trained model
model = joblib.load("../model/ddos_xgboost.pkl")

# Load feature names
feature_names = joblib.load("../model/feature_names.pkl")


@app.route("/")
def home():
    return jsonify({
        "message": "DDoS Detection API is running"
    })


@app.route("/predict", methods=["POST"])
def predict():

    try:
        # Get JSON data from request
        data = request.get_json()

        # Create DataFrame using the correct feature order
        input_data = pd.DataFrame([data])

        # Make sure all required features are present
        input_data = input_data[feature_names]

        # Make prediction
        prediction = model.predict(input_data)[0]

        # Convert prediction to readable result
        if prediction == 1:
            result = "DDoS"
        else:
            result = "BENIGN"

        return jsonify({
            "prediction": result
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 400


if __name__ == "__main__":
    app.run(debug=True)