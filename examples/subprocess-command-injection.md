# Command injection through subprocess

A "network check" endpoint that runs `ping` through a shell, what `es-python`
reports when request data reaches the command, and the fix.

## The vulnerable code

Save this as `app.py`:

```python
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10
    )
    return {"output": result.stdout}


if __name__ == "__main__":
    app.run(port=5000)
```

`shell=True` hands the whole string to `/bin/sh`, so anything the shell treats
as syntax (`;`, `|`, `$( )`, backticks) is executed, not passed to `ping`.

## Run it under es-python

Set the **socket** source to **On** in the machine's **Configure** window, then:

```bash
es-python app.py
```

```bash
curl --get http://127.0.0.1:5000/ping --data-urlencode "host=127.0.0.1"
curl --get http://127.0.0.1:5000/ping --data-urlencode "host=127.0.0.1; id"
```

The second request runs `id` on the server, as the user the app runs as, and
the output comes back in the response.

## What es-python reports

The event has the sink label `subprocess shell`, the impact tag
`command injection` and the severity **Critical**. Its **What this means**
block reads:

> **What happened:** `subprocess.Popen() / os.posix_spawn()`: Data that came in
> over the network was used to run a command on the operating system.
>
> **Why this is risky:** An attacker who can send data to this program over the
> network may use this command injection to run operating-system commands on
> the machine, as the user this program runs as.
>
> **What to do:** Do not build a command line out of this value. Use
> `subprocess.run([prog, arg])` with a list and no `shell=True`, so the shell
> never sees it.

The sentence names two calls because one check covers both ways a process can
be started, and the event does not say which one ran. Below it:

| Block | What it shows here |
|---|---|
| **Command line** | `es-python app.py` |
| **Repr found** | the command as the shell received it, `ping -c 1 127.0.0.1; id` |
| **Repr created** | the request data as it first arrived from the network |
| **Stack trace** | the calls from the `ping` view down into `subprocess` |
| **Origin** | the network connection the request came in on |

One call can produce more than one row. You may also see companion events for
the same call, such as `shell injection`. Each is the same flow seen from a
different angle, and each is its own row because its sink label differs. A
**Hide** rule or the **Tag** filter (`command injection`) keeps the list tidy
while you work through them.

The values above describe this example; your trace and counts will differ. See
[Event detail](https://eyalsec.com/docs/event-detail).

## Block it instead of only reporting it

Add a **Raise (machine)** rule whose pattern matches the label, for example
`^subprocess shell$`, and the program gets a `RuntimeError` at that call
instead of carrying on. The user guide notes that at a small number of
operations that cannot be interrupted part-way, the error is raised immediately
after the operation rather than before it; see
[Report and Raise](https://eyalsec.com/docs/report-and-raise). The code fix
below is what removes the risk.

## The fix

Two changes. Drop the shell by passing a list, so the value can only ever be one
argument to `ping`. Then validate the value as what it is meant to be, an IP
address, so attacker input never reaches the call at all:

```python
import ipaddress
import subprocess
from flask import Flask, request, abort

app = Flask(__name__)


@app.get("/ping")
def ping():
    raw = request.args.get("host", "")
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        abort(400, "host must be an IP address")
    result = subprocess.run(
        ["ping", "-c", "1", str(addr)], capture_output=True, text=True, timeout=10
    )
    return {"output": result.stdout}
```

Why both: the list form alone stops the shell, but the value is still the
attacker's and still reaches `ping` as an argument. A value starting with `-`
would be read as an option. `es-python` can still report request data reaching
a process launch in that case, on purpose: the data is still untrusted. The
validation is what keeps it out.

## Related

- [Command injection in Python](https://eyalsec.com/vulnerabilities/command-injection)
- [Ready-made rule templates](https://eyalsec.com/docs/rule-templates#ready-made),
  including one for blocking critical attacks
