import requests
import time

URL = "http://127.0.0.1:5001/"


def generate_normal_traffic():
    print("Generating normal traffic...")

    for i in range(10):
        response = requests.get(URL)

        print(
            f"Request {i + 1}: "
            f"Status {response.status_code}"
        )

        time.sleep(1)


def generate_high_traffic():
    print("Generating controlled high traffic...")

    for i in range(50):
        response = requests.get(URL)

        print(
            f"Request {i + 1}: "
            f"Status {response.status_code}"
        )

        time.sleep(0.05)


print("===== TRAFFIC GENERATOR =====")
print("1. Normal Traffic")
print("2. Controlled High Traffic")

choice = input("Enter your choice: ")

if choice == "1":
    generate_normal_traffic()

elif choice == "2":
    generate_high_traffic()

else:
    print("Invalid choice.")