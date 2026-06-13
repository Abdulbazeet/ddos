

import os
import tempfile

from flask import Flask
from flask import request
from flask import jsonify
from flask import send_from_directory

from flask_cors import CORS

import sys

# =========================
# IMPORT ANALYZER
# =========================

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from predict import analyze_pcap
# =========================
# APP CONFIG
# =========================

app = Flask(__name__)

CORS(app)

UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =========================
# HOME ROUTE
# =========================

@app.route("/")

def home():

    return jsonify({
        "message": "CNN-LSTM DDoS Detection API Running"
    })

# =========================
# ANALYZE ROUTE
# =========================

@app.route("/analyze", methods=["POST"])

def analyze():

    if "file" not in request.files:

        return jsonify({
            "error": "No file uploaded"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "error": "Empty filename"
        }), 400

    # =========================
    # SAVE TEMP FILE
    # =========================

    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".pcap"
    )

    file.save(temp_file.name)

    try:

        result = analyze_pcap(temp_file.name)

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        os.remove(temp_file.name)

# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )