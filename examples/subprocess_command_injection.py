"""Command injection through subprocess, and the fixed version beside it.

Deliberately vulnerable. Run it only on a machine you are allowed to test.

    es-python subprocess_command_injection.py
    curl --get http://127.0.0.1:5000/ping       --data-urlencode "host=127.0.0.1; id"
    curl --get http://127.0.0.1:5000/ping-fixed --data-urlencode "host=127.0.0.1; id"

The first request runs `id` on the server and is reported as
`subprocess shell`. The second is refused with a 400 before any process starts.
Walkthrough: subprocess-command-injection.md
"""
import ipaddress
import os
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args.get("host", "")
    # VULNERABLE: shell=True hands the whole string to /bin/sh.
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10
    )
    return {"output": result.stdout}


@app.get("/ping-fixed")
def ping_fixed():
    raw = request.args.get("host", "")
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        abort(400, "host must be an IP address")
    # FIXED: no shell, and the value is validated as what it is meant to be.
    result = subprocess.run(
        ["ping", "-c", "1", str(addr)], capture_output=True, text=True, timeout=10
    )
    return {"output": result.stdout}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
