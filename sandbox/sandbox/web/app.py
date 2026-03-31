from flask import Flask, jsonify
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logs.logger import get_stats

app = Flask(__name__)

@app.route("/api/stats")
def stats():
    return jsonify(get_stats())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
