"""Minimal Flask fixture used by discovery tests.

Expected discovery:
- Two HTTP_ROUTE entry points with framework="flask"
- GET / -> index()
- POST /submit -> submit()
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return "hello"


@app.route("/submit", methods=["POST"])
def submit():
    return request.form.get("x", "")
