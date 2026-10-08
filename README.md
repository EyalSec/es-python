![EyalSec es-python - a secure Python](https://raw.githubusercontent.com/EyalSec/es-python/main/banner.png)

# es-python

**The EyalSec Python runtime: run your existing Python app through it, unchanged, and it reports or blocks attacker-controlled data reaching a SQL query, a shell command, a deserializer, a file path or a dynamic import.**

[![Website](https://img.shields.io/badge/website-eyalsec.com-e8b04b)](https://eyalsec.com)
[![Docs](https://img.shields.io/badge/docs-user%20guide-2a2c27)](https://eyalsec.com/docs)

`es-python` is the runtime behind [EyalSec](https://eyalsec.com). You install it
next to your normal Python and run your existing programs and libraries through
it unchanged: `es-python app.py` instead of `python app.py`. While your program
runs, `es-python` follows untrusted data from where it entered (a network
request, a file, standard input, an environment variable) to the operation that
uses it, and either reports the flow to your dashboard or stops the operation.

**Who it is for:** AppSec and security engineers, and the backend teams they
work with, running Python services (Django, Flask, FastAPI, Celery workers,
internal tools) that hold data worth stealing.

## What it catches

The untrusted-data-reaches-a-risky-operation pattern behind most real-world
attacks:

- [SQL injection](https://eyalsec.com/vulnerabilities/sql-injection), including
  through the real database drivers your app uses, and second-order SQL
  injection through data read back from your own database
- [Command injection](https://eyalsec.com/vulnerabilities/command-injection),
  and the shapes around it: shell metacharacters, argument injection,
  environment and `PATH` tampering
- [Path traversal](https://eyalsec.com/vulnerabilities/path-traversal),
  null-byte injection, zip and tar extraction escapes
- [Insecure deserialization](https://eyalsec.com/vulnerabilities/insecure-deserialization)
  (`pickle`, `marshal`, `yaml`, `jsonpickle`)
- [Server-side code injection](https://eyalsec.com/vulnerabilities/code-injection)
  (`exec` / `eval` / `compile` / dynamic import)
- [SSRF](https://eyalsec.com/vulnerabilities/ssrf), CRLF header injection, and
  log forging
- Server-side template injection, XXE, XPath and LDAP filter injection
- NoSQL injection (MongoDB, Redis Lua `eval`, Cypher)
- Weak hashes and KDFs, timing-unsafe secret comparison, predictable tokens
- Hardcoded credentials, reported where they *leave* the process
- Code loaded from a file another user on the machine can write

## A short example

A Flask search endpoint that builds its SQL from the query string:

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.get("/products")
def search_products():
    term = request.args.get("q", "")
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(
        f"SELECT id, name, price FROM products WHERE name LIKE '%{term}%'"
    ).fetchall()
    conn.close()
    return jsonify(rows)
```

Save it as `app.py` and run it with `es-python -m flask run`, with the
**socket** source switched on. A request whose `q` is `%' OR 1=1 --` turns the
search into "every product" and produces one event. Opened on the dashboard, it
reads (abridged):

> **Severity:** Critical · **Event:** `sqlite execute` · **Impact tag:** `sqli`
>
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

Below that come the evidence blocks: **Repr found** (the query text as it
reached the database), **Repr created** (the request data as it first arrived),
the **Stack trace** down to `search_products`, the **Origin** (the network
connection) and the **Command line** that started the program. The fix is one
line:

```python
rows = conn.execute(
    "SELECT id, name, price FROM products WHERE name LIKE ?", (f"%{term}%",)
).fetchall()
```

The value now travels as a parameter and is never part of the query text.
Three full walkthroughs (SQL injection in Flask, command injection through
`subprocess`, and `pickle` deserialization) are in [`examples/`](examples/).

## Coverage

Detection runs inside your program as it executes, not beside it, with **173
sink checks**, each watching one dangerous operation.

**Real database drivers, not just `sqlite3`.** `es-python` covers the drivers
applications actually use, each checked on the statement text:

| Database | Driver |
|---|---|
| PostgreSQL | `psycopg2`, `psycopg` v3 |
| MySQL / MariaDB | `mysqlclient`, `mariadb` |
| Oracle | `oracledb` |
| LDAP | `python-ldap` |

(`psycopg` v3 and `mysqlclient` are included from Python 3.10.)

**19 third-party libraries** have checks of their own: Django, Flask/Jinja2,
SQLAlchemy, PyMongo, Redis, Neo4j, asyncpg, PyJWT, PyYAML, Paramiko, Cassandra,
ClickHouse and more. When a new release of one of them renames a method that
`es-python` watches, the gap is **reported back to EyalSec**, not silently
dropped.

## Two severe CVEs in Django

The engine has flagged two severe SQL-injection CVEs in Django:

| CVE | What it is | Severity |
|---|---|---|
| [CVE-2024-42005](https://nvd.nist.gov/vuln/detail/CVE-2024-42005) | SQL injection in `QuerySet.values()` / `values_list()` on a `JSONField`, through a crafted JSON key used as a column alias | CVSS 7.3, High per NVD (CISA rates it 9.8, Critical) |
| [CVE-2025-57833](https://nvd.nist.gov/vuln/detail/CVE-2025-57833) | SQL injection through `FilteredRelation` column aliases in `QuerySet.annotate()` / `alias()` with `**kwargs` expansion | CVSS 8.1, High per NVD |

Both are in a dependency, not in application code. The same check that watches
your own queries watches the libraries you import.

## Why it does not drown you in false positives

This is the part that decides whether a tool gets used.

- **A sink fires on the statement, never on a bound parameter.** Correctly
  parameterized code stays silent no matter how hostile the value is.
- **`es-python` knows what a sanitizer fixed, per sink.** Escaping is not
  global: `urlencode` neutralizes a URL context and does nothing for SQL, and
  the engine grades it that way instead of suppressing a real finding or
  reporting a fixed one.
- **A detection means the data actually arrived.** Not that a path exists, not
  that a pattern matched.

Coverage limits are documented rather than papered over. LDAP is the clearest
example: it has no bind-parameter mechanism, so even the correct
`filter_format` call splices the escaped value into the filter string. The
event therefore claims "attacker data reached the LDAP filter", not "injection
proven", and says so.

## How it differs from static analysis

A static scanner reads your source before it runs and reasons about what might
happen. `es-python` watches your program as it really runs and reports only
untrusted data that actually reached a risky operation, with the path from where
it entered to where it was used. The list is shorter, every item comes with
evidence, and the dangerous operation can be stopped at runtime.

## Limits worth knowing

- **Every source starts off.** A fresh install reports nothing until you switch
  on the sources you want watched (network, files, standard input, environment).
- **An event is a reachability fact, not a proof of exploitability.** It says
  attacker-controlled data reached the operation, and shows the trace. Logic
  upstream (an allow-list check, say) can still make the flow harmless. You
  judge it; the evidence is there to judge with.
- **Watching data costs CPU.** The cost grows with the sources you switch on,
  and a file-heavy program watching every file read pays the most. Measure it on
  your own workload.
- **Linux only**, on x86_64 and aarch64, for Python 3.9 to 3.14.
- **Blocking is opt-in.** Report and Raise has to be enabled on your account,
  and at a small number of operations that cannot be interrupted part-way the
  error is raised immediately after the operation instead of before it.

## See it working

**[EyalSec/vulnerable-python](https://github.com/EyalSec/vulnerable-python)** is
a deliberately vulnerable Flask app where every endpoint wires one source of
untrusted data into one risky operation. Run the same unchanged file under your
normal Python and it is a normal exploitable app; run it under `es-python` and
every attack that reaches a sink is reported.

## Getting access

There is no self-serve plan and no trial. Access starts with a conversation:
**[Book a live demo](https://eyalsec.com/contact)**. Your plan is sized with you
there; pricing is metered by machines and events
([eyalsec.com/pricing](https://eyalsec.com/pricing)).

Once a plan is set up on your account:

1. On the **Machines** page of your dashboard, add a machine: a name, its Linux
   distribution, its architecture and the Python version.
2. Click **Install**, copy the one-line command (its one-time token is valid for
   10 minutes) and run it in a terminal on that machine. `es-python` installs in
   your home directory, next to your normal Python, which is left as it was.
3. Click **Configure** and switch on the sources you want watched, for example
   **socket** for a web service.
4. Run your program with `es-python` wherever you would type `python`:
   `es-python app.py`, `es-python -m flask run`, `es-python -m pytest`.
5. Watch the **Events** page. To block instead of only reporting, add a
   **Raise** rule for the operations you want stopped.

Full walkthrough: **[Quick start](https://eyalsec.com/docs/quick-start)**.

## Learn more

- **[Documentation](https://eyalsec.com/docs)**: install, run, read events,
  write rules, use the API
- **[Research](https://eyalsec.com/research)**: write-ups on Python injection and
  runtime detection
- **[Vulnerability guides](https://eyalsec.com/vulnerabilities)**: what each
  injection class looks like in Python code, and how to fix it
- **[Python injection checker](https://eyalsec.com/tools/python-injection-checker)**:
  a browser-side tool for checking Python code for injection risks
- **[Security](https://eyalsec.com/security)**: what leaves your machine, and
  how it is protected

## About this repository

This repository is the public home and documentation for `es-python`. The
runtime is delivered to your machines through the EyalSec dashboard installer;
there is no source to build here. Start at **[eyalsec.com](https://eyalsec.com)**.

---

Python is a trademark of the Python Software Foundation. EyalSec is not
affiliated with or endorsed by the PSF.
