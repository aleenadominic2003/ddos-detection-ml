import os
from collections import Counter
from datetime import datetime

LOG_FILE = "demo_app/logs/traffic.log"


def analyze_traffic():

    if not os.path.exists(LOG_FILE):
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "peak_rps": 0,
            "average_response_time": 0,
            "endpoint_counts": {}
        }

    requests = []

    with open(LOG_FILE, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split("|")]

            if len(parts) != 6:
                continue

            timestamp = parts[0]
            ip = parts[1]
            endpoint = parts[2]
            method = parts[3]
            status = parts[4]
            response_time = parts[5]

            requests.append({
                "timestamp": datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                ),
                "ip": ip,
                "endpoint": endpoint,
                "method": method,
                "status": status,
                "response_time": float(
                    response_time.replace("s", "")
                )
            })

    if not requests:
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "peak_rps": 0,
            "average_response_time": 0,
            "endpoint_counts": {}
        }

    # -----------------------------
    # Basic statistics
    # -----------------------------

    total_requests = len(requests)

    unique_ips = len(
        set(request["ip"] for request in requests)
    )

    endpoint_counts = Counter(
        request["endpoint"] for request in requests
    )

    average_response_time = sum(
        request["response_time"]
        for request in requests
    ) / total_requests

    # -----------------------------
    # Calculate peak requests/sec
    # -----------------------------

    timestamps = sorted(
        request["timestamp"]
        for request in requests
    )

    peak_rps = 0

    for current_time in timestamps:

        one_second_later = current_time.timestamp() + 1

        count = sum(
            timestamp.timestamp() < one_second_later
            and timestamp.timestamp() >= current_time.timestamp()
            for timestamp in timestamps
        )

        if count > peak_rps:
            peak_rps = count

    # -----------------------------
    # Return results
    # -----------------------------

    return {
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "peak_rps": peak_rps,
        "average_response_time": round(
            average_response_time,
            4
        ),
        "endpoint_counts": dict(endpoint_counts)
    }


if __name__ == "__main__":

    result = analyze_traffic()

    print("\n===== TRAFFIC ANALYSIS =====")

    print(
        f"Total Requests          : "
        f"{result['total_requests']}"
    )

    print(
        f"Unique IPs              : "
        f"{result['unique_ips']}"
    )

    print("\nRequests by Endpoint:")

    for endpoint, count in result["endpoint_counts"].items():
        print(f"  {endpoint} : {count}")

    print(
        f"\nAverage Response Time   : "
        f"{result['average_response_time']:.4f} seconds"
    )

    print(
        f"Peak Requests/Second    : "
        f"{result['peak_rps']}"
    )