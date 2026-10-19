"""SQL injection in a Flask endpoint, and the fixed version beside it.

Deliberately vulnerable. Run it only on a machine you are allowed to test.

    es-python flask_sql_injection.py
    curl --get http://127.0.0.1:5000/products       --data-urlencode "q=%' OR 1=1 --"
    curl --get http://127.0.0.1:5000/products-fixed --data-urlencode "q=%' OR 1=1 --"

The first request is reported as `sqlite execute`. The second is silent:
the value travels as a bound parameter and never becomes query text.
Walkthrough: flask-sql-injection.md
"""
import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = "shop.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)"
    )
    conn.execute("DELETE FROM products")
    conn.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [("lamp", 39.0), ("desk", 249.0), ("internal-test-sku", 0.0)],
    )
    conn.commit()
    conn.close()


@app.get("/products")
def search_products():
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    # VULNERABLE: the search term becomes part of the SQL text.
    rows = conn.execute(
        f"SELECT id, name, price FROM products WHERE name LIKE '%{term}%'"
    ).fetchall()
    conn.close()
    return jsonify(rows)


@app.get("/products-fixed")
def search_products_fixed():
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    # FIXED: the query text is a constant; the value is a parameter.
    rows = conn.execute(
        "SELECT id, name, price FROM products WHERE name LIKE ?",
        (f"%{term}%",),
    ).fetchall()
    conn.close()
    return jsonify(rows)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
