# SQL injection in a Flask endpoint

A search endpoint that builds its SQL from the query string, what `es-python`
reports when request data reaches the query, and the one-line fix.

## The vulnerable code

Save this as `app.py`. It creates a small SQLite database on first run, so it is
self-contained.

```python
import sqlite3
from flask import Flask, request, jsonify

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
    rows = conn.execute(
        f"SELECT id, name, price FROM products WHERE name LIKE '%{term}%'"
    ).fetchall()
    conn.close()
    return jsonify(rows)


if __name__ == "__main__":
    init_db()
    app.run(port=5000)
```

The search term goes straight into the SQL text. Whoever controls `q` controls
the query.

## Run it under es-python

On the dashboard, open **Configure** for the machine and set the **socket**
source to **On** (every source starts off). Then start the app the way you
would with `python`:

```bash
es-python app.py
```

Send a normal search, then one that rewrites the query:

```bash
curl --get http://127.0.0.1:5000/products --data-urlencode "q=lamp"
curl --get http://127.0.0.1:5000/products --data-urlencode "q=%' OR 1=1 --"
```

The second request returns every row, including the one a search for a product
name should never reach.

## What es-python reports

The event appears on the **Events** page with the sink label `sqlite execute`,
the impact tag `sqli` and the severity **Critical**: severity weighs how easily
an attacker controls the source (a network request is the easiest) against how
much damage the sink can do (a database query can do a lot). Opened, its
**What this means** block reads:

> **What happened:** `sqlite3.Cursor.execute()`: Data that came in over the
> network was used to build a database query.
>
> **Why this is risky:** An attacker who can send data to this program over the
> network may use this SQL injection to read or change any data in the
> database, and get past checks such as who may see which row.
>
> **What to do:** Never build SQL by joining strings or with f-strings. Use
> placeholders (`?` or `%s`) and pass the value as a parameter, so the database
> always treats it as data.

Under it, the evidence:

| Block | What it shows here |
|---|---|
| **Command line** | `es-python app.py`, and how many of the event's occurrences came from that run |
| **Repr found** | the query text as it reached the database, with the attacker's `' OR 1=1 --` inside it |
| **Repr created** | the request data as it first arrived from the network, before Flask parsed it |
| **Stack trace** | the calls that led to the query, ending in `search_products` in `app.py` |
| **Origin** | the network connection the request came in on |

Comparing **Repr created** with **Repr found** shows what the program did to the
data on the way: here, URL decoding and an f-string. Send the same request
again and the event's count goes up instead of a new row appearing.

The values above describe this example; your trace, paths and counts will
differ. Every block is described in
[Event detail](https://eyalsec.com/docs/event-detail).

## Block it instead of only reporting it

Report mode records the flow and lets the query run. To stop it, add a rule in
**Configure** with the pattern `^sqlite execute$` and the mode
**Raise (machine)** (Raise must be enabled on your account). Within about 30
seconds the running app picks it up. The same request then gets a
`RuntimeError` at the `execute` call instead of running the query, of the form:

```
RuntimeError: EyalSec: untrusted data from <source> reached sink sqlite execute
```

Flask turns the uncaught error into a 500 response, and the event is still
recorded, so you see what was blocked. See
[Report and Raise](https://eyalsec.com/docs/report-and-raise).

## The fix

Pass the value as a parameter. The `%` wildcards belong to the value, not to
the SQL:

```python
@app.get("/products")
def search_products():
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT id, name, price FROM products WHERE name LIKE ?",
        (f"%{term}%",),
    ).fetchall()
    conn.close()
    return jsonify(rows)
```

The query text is now a constant. The request data travels to the database as a
bound parameter and is never parsed as SQL, so the injection is gone and there
is no request data in the statement for this check to report.

## Related

- [SQL injection in Python](https://eyalsec.com/vulnerabilities/sql-injection)
- [Taint sources](https://eyalsec.com/docs/taint-sources): what **socket** and
  the other sources mark
- [Rules](https://eyalsec.com/docs/rules): hide a flow you expect, or block one
