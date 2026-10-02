from flask import Flask, render_template, request
from datetime import datetime
import time
import os

app = Flask(__name__)

# Create logs folder
os.makedirs("demo_app/logs", exist_ok=True)

LOG_FILE = "demo_app/logs/traffic.log"


@app.before_request
def start_timer():
    request.start_time = time.time()


@app.after_request
def log_request(response):

    response_time = time.time() - request.start_time

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.remote_addr
    endpoint = request.path
    method = request.method
    status_code = response.status_code

    log_entry = (
        f"{timestamp} | "
        f"{client_ip} | "
        f"{endpoint} | "
        f"{method} | "
        f"{status_code} | "
        f"{response_time:.4f}s\n"
    )

    with open(LOG_FILE, "a") as file:
        file.write(log_entry)

    return response


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/products")
def products():
    return render_template("products.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(port=5001, debug=True)