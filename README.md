![EyalSec es-python - a secure Python](https://raw.githubusercontent.com/EyalSec/es-python/main/banner.png)

# es-python

**A security-hardened build of Python that detects and blocks injection attacks as your code runs.**

[![Website](https://img.shields.io/badge/website-eyalsec.com-e8b04b)](https://eyalsec.com)
[![Docs](https://img.shields.io/badge/docs-user%20guide-2a2c27)](https://eyalsec.com/docs)

`es-python` is the runtime behind [EyalSec](https://eyalsec.com). You install it
next to your normal Python and run your existing programs and libraries through
it unchanged. While your program runs, `es-python` watches for untrusted data
reaching a risky action, and either reports it to your dashboard or blocks it
before it runs.

## What it catches

The untrusted-data-reaches-a-sink pattern behind most real-world attacks:

- SQL injection, including through the real database drivers your app uses
- Command injection, and the shapes around it: shell metacharacters, argument
  injection, environment and `PATH` tampering
- Path traversal, null-byte injection, zip and tar extraction escapes
- Insecure deserialization (`pickle`, `marshal`, `yaml`, `jsonpickle`)
- Server-side code injection (`exec` / `eval` / `compile` / dynamic import)
- SSRF, CRLF header injection, and log forging
- Server-side template injection, XXE, XPath and LDAP filter injection
- NoSQL injection (MongoDB `$where`, Redis Lua `eval`, Cypher)
- Weak hashes and KDFs, timing-unsafe secret comparison, predictable tokens
- Hardcoded credentials, but reported where they *leave* the process
- Code loaded from a file another user can write

It has already flagged two critical CVEs in Django.

## Coverage

Detection runs inside your program as it executes, not beside it: **173 sink
call sites**, each watching one dangerous operation.

**Real database drivers, not just `sqlite3`.** `es-python` ships instrumented
builds of the drivers applications actually use, each with the sink on the
statement string:

| Database | Driver |
|---|---|
| PostgreSQL | `psycopg2`, `psycopg` v3 |
| MySQL / MariaDB | `mysqlclient`, `mariadb` |
| Oracle | `oracledb` |
| LDAP | `python-ldap` |

**42 third-party libraries** are covered by declarative adapters: Django,
Flask/Jinja2, SQLAlchemy, PyMongo, Redis, Neo4j, asyncpg, PyJWT, PyYAML,
Paramiko, Cassandra, ClickHouse and more. Adding a library is a registry entry,
not a fork. When an upstream release renames a method out from under an
adapter, the miss is **reported to your dashboard**, not silently dropped.

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

A static scanner reads your source before it runs and guesses at possible bugs.
`es-python` watches your program as it really runs and only reports untrusted
data that actually reaches a risky action, so it finds real, exploitable issues
with far fewer false positives, and can block them at runtime.

## See it working

**[EyalSec/vulnerable-python](https://github.com/EyalSec/vulnerable-python)** is
a deliberately vulnerable Flask app where every endpoint wires one taint source
into one sink. Run the same unchanged file under your normal Python and it is a
normal exploitable app; run it under `es-python` and every attack that reaches a
sink is reported.

## Quickstart

1. Sign in and add a machine on your [EyalSec dashboard](https://eyalsec.com).
2. Run the one-line installer it gives you. `es-python` installs next to your
   normal Python.
3. Run your application with `es-python` instead of `python`. Your code and
   libraries run unchanged.
4. Watch detections on your dashboard, and switch a machine to Report and Raise
   mode to block risky actions while still logging them.

Full guide: **[eyalsec.com/docs](https://eyalsec.com/docs)**.

## About this repository

This repository is the public home and documentation for `es-python`. The
runtime is delivered to your machines through the EyalSec dashboard installer;
there is no source to build here. Start at **[eyalsec.com](https://eyalsec.com)**.

---

Python is a trademark of the Python Software Foundation. EyalSec is not
affiliated with or endorsed by the PSF.
