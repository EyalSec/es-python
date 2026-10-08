# es-python examples

Three short walkthroughs. Each one is a small Flask app with one real
vulnerability, the request that exercises it, what `es-python` reports for it on
the dashboard, and the fix.

| Example | The flaw | Sink label you will see |
|---|---|---|
| [SQL injection in a Flask endpoint](flask-sql-injection.md) | a search term pasted into SQL with an f-string | `sqlite execute` |
| [Command injection through subprocess](subprocess-command-injection.md) | a host name pasted into a `shell=True` command | `subprocess shell` |
| [Pickle deserialization of request data](pickle-deserialization.md) | a request body passed to `pickle.loads` | `pickle loads` |

## Before you run them

- You need a machine with `es-python` installed from your EyalSec dashboard,
  and Flask installed for the same Python version (`es-python -m pip install
  flask`). See [Quick start](https://eyalsec.com/docs/quick-start).
- Switch on the **socket** source for that machine. Every source starts off, so
  without it nothing is reported.
- Run each app on a machine you are allowed to test, and stop it when you are
  done: the vulnerable versions really are vulnerable.

## Reading the event

The quoted **What happened**, **Why this is risky** and **What to do** text is
what the dashboard's event detail shows for these flows. The tables of evidence
blocks describe what each block holds in the example; exact values (paths,
traces, counts) depend on your machine. Every block is explained in
[Event detail](https://eyalsec.com/docs/event-detail).

No access yet? There is no self-serve plan:
[book a live demo](https://eyalsec.com/contact).
