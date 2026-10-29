def respond(ddos_flows, peak_flow_rate, average_flow_rate):

    print("\n==============================")
    print("AUTOMATED RESPONSE ENGINE")
    print("==============================")

    # Level 1: Confirmed DDoS
    if ddos_flows > 0:

        print("🚨 SECURITY ALERT")
        print("DDoS attack detected.")
        print("Affected flows:", ddos_flows)

        if ddos_flows >= 5:
            print("Threat level: HIGH")
            print("Response: BLOCK / RATE LIMIT SUSPICIOUS TRAFFIC")

        else:
            print("Threat level: MEDIUM")
            print("Response: ALERT + MONITOR SUSPICIOUS FLOWS")

    # Level 2: High traffic but ML says benign
    elif peak_flow_rate > 1500:

        print("⚠️ HIGH TRAFFIC DETECTED")
        print("ML classification: BENIGN")
        print("Threat level: LOW")
        print("Response: CONTINUE MONITORING")

    # Level 3: Normal traffic
    else:

        print("✅ NORMAL TRAFFIC")
        print("Threat level: LOW")
        print("Response: ALLOW TRAFFIC")

    print("==============================")