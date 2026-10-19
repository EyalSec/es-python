"""Pickle deserialization of a request body, and the fixed version beside it.

Deliberately vulnerable. Run it only on a machine you are allowed to test.

    es-python pickle_deserialization.py
    python3 -c 'import pickle, sys; sys.stdout.buffer.write(pickle.dumps({"items": [1, 2]}))' \
      | curl --data-binary @- http://127.0.0.1:5000/cart/restore
    curl -d '{"items": [1, 2]}' http://127.0.0.1:5000/cart/restore-fixed

The first request is reported as `pickle loads` even though the cart is
harmless: the finding is where the bytes came from. The second is silent.
Walkthrough: pickle-deserialization.md
"""
import json
import os
import pickle

from flask import Flask, abort, request

app = Flask(__name__)


@app.post("/cart/restore")
def restore_cart():
    # VULNERABLE: unpickling can call functions named inside the data.
    cart = pickle.loads(request.get_data())
    return {"items": len(cart.get("items", []))}


@app.post("/cart/restore-fixed")
def restore_cart_fixed():
    # FIXED: JSON builds only dicts, lists, strings, numbers, booleans and None.
    try:
        cart = json.loads(request.get_data())
    except ValueError:
        abort(400, "cart must be JSON")
    items = cart.get("items", []) if isinstance(cart, dict) else []
    return {"items": len(items)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
