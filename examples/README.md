# es-python examples

Five short walkthroughs. Each is one small app with one real vulnerability and
its fix side by side: the request that exercises it, what `es-python` reports
on the dashboard, and why the fixed route stays silent.

| Example | Framework | The flaw | Sink label you will see |
|---|---|---|---|
| [SQL injection](flask-sql-injection.md) ([code](flask_sql_injection.py)) | Flask | a search term pasted into SQL with an f-string | `sqlite execute` |
| [SQL injection through raw()](django-raw-sql.md) ([code](django_raw_sql.py)) | Django | a request value formatted into `QuerySet.raw()` | `sql raw` |
| [SSRF](fastapi-ssrf.md) ([code](fastapi_ssrf.py)) | FastAPI | a URL from the request fetched by the server | `ssrf` |
| [Command injection](subprocess-command-injection.md) ([code](subprocess_command_injection.py)) | Flask | a host name pasted into a `shell=True` command | `subprocess shell` |
| [Pickle deserialization](pickle-deserialization.md) ([code](pickle_deserialization.py)) | Flask | a request body passed to `pickle.loads` | `pickle loads` |

## Before you run them

- You need a machine with `es-python` installed from your EyalSec dashboard,
  and the framework installed for the same Python version (for example
  `es-python -m pip install flask`). See
  [Quick start](https://eyalsec.com/docs/quick-start).
- A new machine watches network input (**socket**) from the start, which is the
  source these examples use. If you switched it off, switch it on in
  **Configure**.
- Each file listens on `127.0.0.1` only. Set `PORT` to change the port. Run
  them on a machine you are allowed to test, and stop them when you are done:
  the vulnerable routes really are vulnerable.

## Reading the event

The quoted **What happened**, **Why this is risky** and **What to do** text is
what the dashboard's event detail shows for these flows. The tables of evidence
blocks describe what each block holds in the example; exact values (paths,
traces, counts) depend on your machine. Every block is explained in
[Event detail](https://eyalsec.com/docs/event-detail).

No access yet? Plans are set up with you:
[book a live demo](https://eyalsec.com/contact).
