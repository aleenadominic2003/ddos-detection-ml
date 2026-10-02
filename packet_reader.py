import subprocess
import pandas as pd
import numpy as np
import joblib

from response_engine import respond

# ============================================================
# CONFIGURATION
# ============================================================

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
PCAP_FILE = r"demo_app\captures\test_attack.pcapng"

# Features expected by the trained XGBoost model
FEATURE_NAMES = joblib.load("model/feature_names.pkl")


# ============================================================
# READ PACKETS FROM PCAP
# ============================================================

def read_packets():

    command = [
        TSHARK,
        "-r", PCAP_FILE,
        "-Y", "tcp.port == 5001",
        "-T", "fields",

        "-e", "tcp.stream",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "frame.len",
        "-e", "tcp.len",
        "-e", "tcp.hdr_len",
        "-e", "tcp.flags.ack",
        "-e", "tcp.window_size_value"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    rows = []

    for line in result.stdout.strip().splitlines():

        parts = line.split("\t")

        if len(parts) < 11:
            continue

        try:

            rows.append({
                "stream": int(parts[0]),
                "time": float(parts[1]),
                "src": parts[2],
                "dst": parts[3],
                "src_port": int(parts[4]),
                "dst_port": int(parts[5]),
                "frame_len": float(parts[6]),
                "tcp_len": float(parts[7]),
                "tcp_hdr_len": float(parts[8]),
                "ack": parts[9].lower() == "true",
                "window": float(parts[10])
            })

        except ValueError:
            continue

    return pd.DataFrame(rows)


# ============================================================
# CALCULATE FEATURES FOR ONE TCP FLOW
# ============================================================

def calculate_features(df):

    # Server is running on port 5001
    forward = df["dst_port"] == 5001

    fwd = df[forward]
    all_packets = df

    # --------------------------------------------------------
    # 1. Flow Duration
    # --------------------------------------------------------

    flow_duration = (
        df["time"].max() - df["time"].min()
    ) * 1_000_000

    # --------------------------------------------------------
    # 2. Fwd Packet Length Std
    # --------------------------------------------------------

    fwd_packet_std = fwd["frame_len"].std(ddof=1)

    if pd.isna(fwd_packet_std):
        fwd_packet_std = 0

    # --------------------------------------------------------
    # 3. Flow Packets/s
    # --------------------------------------------------------

    duration_seconds = flow_duration / 1_000_000

    if duration_seconds > 0:

        flow_packets_per_sec = (
            len(all_packets) / duration_seconds
        )

    else:

        flow_packets_per_sec = 0

    # --------------------------------------------------------
    # 4. Flow IAT Mean
    # --------------------------------------------------------

    iat = df["time"].diff().dropna()

    if len(iat) > 0:

        flow_iat_mean = (
            iat.mean() * 1_000_000
        )

    else:

        flow_iat_mean = 0

    # --------------------------------------------------------
    # 5. Fwd Header Length
    # --------------------------------------------------------

    fwd_header_length = fwd["tcp_hdr_len"].sum()

    # --------------------------------------------------------
    # Packet length statistics
    # --------------------------------------------------------

    packet_lengths = df["frame_len"]

    # 6. Packet Length Mean

    packet_length_mean = packet_lengths.mean()

    # 7. Packet Length Std

    packet_length_std = packet_lengths.std(ddof=1)

    if pd.isna(packet_length_std):
        packet_length_std = 0

    # 8. Packet Length Variance

    packet_length_variance = packet_lengths.var(ddof=1)

    if pd.isna(packet_length_variance):
        packet_length_variance = 0

    # --------------------------------------------------------
    # 9. ACK Flag Count
    # --------------------------------------------------------

    ack_flag_count = df["ack"].sum()

    # --------------------------------------------------------
    # 10. Subflow Fwd Packets
    # --------------------------------------------------------

    subflow_fwd_packets = len(fwd)

    # --------------------------------------------------------
    # 11. Subflow Fwd Bytes
    # --------------------------------------------------------

    subflow_fwd_bytes = fwd["tcp_len"].sum()

    # --------------------------------------------------------
    # 12. Init_Win_bytes_forward
    # --------------------------------------------------------

    if len(fwd) > 0:

        init_win_bytes_forward = (
            fwd.iloc[0]["window"]
        )

    else:

        init_win_bytes_forward = 0

    # --------------------------------------------------------
    # 13. act_data_pkt_fwd
    # --------------------------------------------------------

    act_data_pkt_fwd = (
        fwd["tcp_len"] > 0
    ).sum()

    # --------------------------------------------------------
    # 14. min_seg_size_forward
    # --------------------------------------------------------

    if len(fwd) > 0:

        min_seg_size_forward = (
            fwd["tcp_hdr_len"].min()
        )

    else:

        min_seg_size_forward = 0

    # --------------------------------------------------------
    # Create feature dictionary
    # --------------------------------------------------------

    features = {

        "Flow Duration": flow_duration,

        "Fwd Packet Length Std": fwd_packet_std,

        "Flow Packets/s": flow_packets_per_sec,

        "Flow IAT Mean": flow_iat_mean,

        "Fwd Header Length": fwd_header_length,

        "Packet Length Mean": packet_length_mean,

        "Packet Length Std": packet_length_std,

        "Packet Length Variance": packet_length_variance,

        "ACK Flag Count": ack_flag_count,

        "Subflow Fwd Packets": subflow_fwd_packets,

        "Subflow Fwd Bytes": subflow_fwd_bytes,

        "Init_Win_bytes_forward": init_win_bytes_forward,

        "act_data_pkt_fwd": act_data_pkt_fwd,

        "min_seg_size_forward": min_seg_size_forward
    }

    return pd.DataFrame([features])


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    print("\n==============================")
    print("LIVE DDoS TRAFFIC ANALYZER")
    print("==============================")

    print("\nReading packets...\n")

    # --------------------------------------------------------
    # Read packets
    # --------------------------------------------------------

    df = read_packets()

    print("Packets captured:", len(df))

    if not df.empty:
        print("TCP streams:", df["stream"].nunique())

    # --------------------------------------------------------
    # Check whether packets exist
    # --------------------------------------------------------

    if df.empty:

        print("\nNo packets found.")
        print("Check the PCAP file or tshark filter.")

        exit()

    # ========================================================
    # PROCESS EVERY TCP STREAM
    # ========================================================

    all_features = []

    stream_ids = sorted(
        df["stream"].unique()
    )

    print("\n==============================")
    print("FLOW PROCESSING")
    print("==============================")

    print(
        "Total TCP streams:",
        len(stream_ids)
    )

    for stream_id in stream_ids:

        stream_df = df[
            df["stream"] == stream_id
        ].copy()

        # Need at least two packets
        if len(stream_df) < 2:
            continue

        flow_features = calculate_features(
            stream_df
        )

        # Store stream ID
        flow_features.insert(
            0,
            "Stream",
            stream_id
        )

        all_features.append(
            flow_features
        )

    # --------------------------------------------------------
    # Check whether flows were created
    # --------------------------------------------------------

    if not all_features:

        print("\nNo valid TCP flows were created.")
        exit()

    # --------------------------------------------------------
    # Combine all flows
    # --------------------------------------------------------

    all_features = pd.concat(
        all_features,
        ignore_index=True
    )

    print("\nFlows processed:", len(all_features))

    # ========================================================
    # FLOW FEATURE SUMMARY
    # ========================================================

    print("\n==============================")
    print("FLOW FEATURE SUMMARY")
    print("==============================")

    print(
        all_features[
            [
                "Stream",
                "Flow Duration",
                "Flow Packets/s",
                "ACK Flag Count",
                "Subflow Fwd Packets",
                "Subflow Fwd Bytes",
                "act_data_pkt_fwd"
            ]
        ].to_string(index=False)
    )

    # ========================================================
    # LOAD XGBOOST MODEL
    # ========================================================

    model = joblib.load(
        "model/ddos_xgboost.pkl"
    )

    # ========================================================
    # PREPARE FEATURES
    # ========================================================

    prediction_features = (
        all_features[FEATURE_NAMES]
    )

    # ========================================================
    # XGBOOST PREDICTION
    # ========================================================

    print("\n==============================")
    print("FEATURES SENT TO XGBOOST")
    print("==============================")

    print(
        prediction_features.iloc[0].to_dict()
    )

    predictions = model.predict(
        prediction_features
    )

    # --------------------------------------------------------
    # Prediction probabilities
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        prediction_features
    )

    # DDoS probability = class 1
    ddos_probabilities = probabilities[:, 1]

    # --------------------------------------------------------
    # Add predictions to table
    # --------------------------------------------------------

    all_features["Prediction"] = [
        "DDoS" if prediction == 1
        else "BENIGN"
        for prediction in predictions
    ]

    all_features["DDoS Probability"] = (
        ddos_probabilities * 100
    )

    # ========================================================
    # FLOW PREDICTIONS
    # ========================================================
    # ========================================================
    # FLOW PREDICTIONS
    # ========================================================

    print("\n==============================")
    print("FLOW PREDICTIONS")
    print("==============================")

    prediction_display = all_features[
        [
            "Stream",
            "Flow Packets/s",
            "ACK Flag Count",
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Prediction",
            "DDoS Probability"
        ]
    ].copy()

    prediction_display["Flow Packets/s"] = (
        prediction_display["Flow Packets/s"].round(2)
    )

    prediction_display["DDoS Probability"] = (
        prediction_display["DDoS Probability"].round(2)
    )

    # --------------------------------------------------------
    # Clean formatted output
    # --------------------------------------------------------

    print(
        prediction_display.to_string(
            index=False,
            formatters={
                "Stream": "{:>6}".format,
                "Flow Packets/s": "{:>14.2f}".format,
                "ACK Flag Count": "{:>15}".format,
                "Subflow Fwd Packets": "{:>20}".format,
                "Subflow Fwd Bytes": "{:>18.1f}".format,
                "Prediction": "{:>12}".format,
                "DDoS Probability": "{:>18.2f}".format
            }
        )
    )

    # ========================================================
    # DETECTION SUMMARY
    # ========================================================

    print("\n==============================")
    print("DETECTION SUMMARY")
    print("==============================")

    total_flows = len(
        all_features
    )

    benign_flows = (
        all_features["Prediction"]
        == "BENIGN"
    ).sum()

    ddos_flows = (
        all_features["Prediction"]
        == "DDoS"
    ).sum()

    print(
        "Total flows:",
        total_flows
    )

    print(
        "BENIGN flows:",
        benign_flows
    )

    print(
        "DDoS flows:",
        ddos_flows
    )

    # ========================================================
    # OVERALL TRAFFIC ASSESSMENT
    # ========================================================

    peak_flow_rate = (
        all_features["Flow Packets/s"].max()
    )

    average_flow_rate = (
        all_features["Flow Packets/s"].mean()
    )

    total_packets = len(df)

    print("\n==============================")
    print("OVERALL TRAFFIC ASSESSMENT")
    print("==============================")

    print(
        "Total packets:",
        total_packets
    )

    print(
        "Total TCP flows:",
        total_flows
    )

    print(
        "Peak flow packets/sec:",
        round(peak_flow_rate, 2)
    )

    print(
        "Average flow packets/sec:",
        round(average_flow_rate, 2)
    )

        # --------------------------------------------------------
    # RISK AND RESPONSE ASSESSMENT
    # --------------------------------------------------------

    # Maximum ML-estimated DDoS probability
    max_ddos_probability = (
        all_features["DDoS Probability"].max()
    )

            # --------------------------------------------------------
    # Determine risk level
    # --------------------------------------------------------

    if ddos_flows > 0:

        risk_level = "CRITICAL"
        traffic_status = "DDoS SUSPICION"
        ml_status = "DDoS DETECTED"
        response = "ALERT / MITIGATE"

    elif max_ddos_probability >= 90:

        risk_level = "CRITICAL"
        traffic_status = "SUSPICIOUS TRAFFIC"
        ml_status = "VERY HIGH DDoS PROBABILITY"
        response = "ALERT"

    elif max_ddos_probability >= 70:

        risk_level = "HIGH"
        traffic_status = "SUSPICIOUS TRAFFIC"
        ml_status = "HIGH DDoS PROBABILITY"
        response = "ALERT"

    elif max_ddos_probability >= 30:

        risk_level = "MEDIUM"
        traffic_status = "SUSPICIOUS TRAFFIC"
        ml_status = "ELEVATED DDoS PROBABILITY"
        response = "MONITOR CLOSELY"

    elif peak_flow_rate > 1500:

        risk_level = "LOW"
        traffic_status = "HIGH TRAFFIC"
        ml_status = "BENIGN"
        response = "MONITOR"

    else:

        risk_level = "LOW"
        traffic_status = "NORMAL"
        ml_status = "BENIGN"
        response = "ALLOW"
    # --------------------------------------------------------
    # Final system assessment
    # --------------------------------------------------------

    print("\n==============================")
    print("SECURITY RISK ASSESSMENT")
    print("==============================")

    print(
        "Maximum DDoS probability:",
        round(max_ddos_probability, 2),
        "%"
    )

    print(
        "Risk level:",
        risk_level
    )

    print(
        "Traffic status:",
        traffic_status
    )

    print(
        "ML status:",
        ml_status
    )

    print(
        "System response:",
        response
    )

    # --------------------------------------------------------
    # Existing response handler
    # --------------------------------------------------------

    respond(
        ddos_flows,
        peak_flow_rate,
        average_flow_rate
    )
    # ========================================================
    # END
    # ========================================================

    print("\n==============================")
    print("ANALYSIS COMPLETE")
    print("==============================")
        # --------------------------------------------------------
    # SAVE RESULTS FOR DASHBOARD
    # --------------------------------------------------------

    import json
    import os

    os.makedirs("demo_app/results", exist_ok=True)

    detection_result = {
        "total_flows": int(total_flows),
        "benign_flows": int(benign_flows),
        "ddos_flows": int(ddos_flows),
        "total_packets": int(total_packets),
        "peak_flow_rate": round(float(peak_flow_rate), 2),
        "average_flow_rate": round(float(average_flow_rate), 2),
        "max_ddos_probability": round(
            float(max_ddos_probability), 4
        ),
        "risk_level": risk_level,
        "traffic_status": traffic_status,
        "ml_status": ml_status,
        "response": response
    }

    with open(
        "demo_app/results/detection_result.json",
        "w"
    ) as file:

        json.dump(
            detection_result,
            file,
            indent=4
        )

    print("\nDetection results saved for dashboard.")