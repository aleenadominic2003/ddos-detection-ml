import requests

url = "http://127.0.0.1:5000/predict"

data = {
    "Flow Duration": 100000,
    "Fwd Packet Length Std": 10,
    "Flow Packets/s": 50,
    "Flow IAT Mean": 20000,
    "Fwd Header Length": 40,
    "Packet Length Mean": 50,
    "Packet Length Std": 10,
    "Packet Length Variance": 100,
    "ACK Flag Count": 1,
    "Subflow Fwd Packets": 5,
    "Subflow Fwd Bytes": 250,
    "Init_Win_bytes_forward": 8192,
    "act_data_pkt_fwd": 5,
    "min_seg_size_forward": 20
}

response = requests.post(url, json=data)

print(response.json())