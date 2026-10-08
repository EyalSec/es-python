# Pickle deserialization of request data

An endpoint that restores a saved cart by unpickling the request body, what
`es-python` reports, and the fix.

## The vulnerable code

Save this as `app.py`:

```python
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.post("/cart/restore")
def restore_cart():
    cart = pickle.loads(request.get_data())
    return {"items": len(cart.get("items", []))}


if __name__ == "__main__":
    app.run(port=5000)
```

It looks harmless with a well-behaved client. It is not: unpickling can call
functions named inside the data, so a crafted body runs code of the sender's
choosing while `pickle.loads` is still loading it. Python's own documentation
says it plainly: only unpickle data you trust.

## Run it under es-python

Set the **socket** source to **On** in the machine's **Configure** window, then:

```bash
es-python app.py
```

You do not need an exploit to see the finding. A perfectly ordinary cart is
enough, because the problem is where the bytes came from, not what they contain:

```bash
python3 -c 'import pickle, sys; sys.stdout.buffer.write(pickle.dumps({"items": [1, 2]}))' \
  | curl --data-binary @- http://127.0.0.1:5000/cart/restore
```

## What es-python reports

The event has the sink label `pickle loads`, the impact tag `rce` and the
severity **Critical**. Its **What this means** block reads:

> **What happened:** `pickle.loads()`: Data that came in over the network was
> loaded and run as program code.
>
> **Why this is risky:** An attacker who can send data to this program over the
> network may use this code injection to run their own code on the machine,
> with every permission this program has.
>
> **What to do:** Do not run data as code. If you need structured input, parse
> it as data (JSON) instead of `eval`/`exec`. If you need to pick behaviour,
> look the input up in a fixed table of allowed choices.

Below it:

| Block | What it shows here |
|---|---|
| **Command line** | `es-python app.py` |
| **Repr found** | the bytes that reached `pickle.loads` |
| **Repr created** | the request data as it first arrived from the network |
| **Stack trace** | the calls from `restore_cart` into `pickle.loads` |
| **Origin** | the network connection the request came in on |

The event fires on the benign cart above for the same reason it would fire on a
malicious one: untrusted bytes reached a deserializer that can run code. That is
the finding. Whether today's traffic happens to be friendly does not change it.

The values above describe this example; your trace and counts will differ. See
[Event detail](https://eyalsec.com/docs/event-detail).

## Block it instead of only reporting it

A **Raise (machine)** rule with the pattern `^pickle loads$` makes the program
get a `RuntimeError` at the `pickle.loads` call instead of carrying on, and the
event is still recorded. See
[Report and Raise](https://eyalsec.com/docs/report-and-raise).

## The fix

Send the cart as JSON and read it as data. Plain `json.loads` builds only
dicts, lists, strings, numbers, booleans and `None`; nothing in the input can
choose code to run.

```python
import json
from flask import Flask, request, abort

app = Flask(__name__)


@app.post("/cart/restore")
def restore_cart():
    try:
        cart = json.loads(request.get_data())
    except ValueError:
        abort(400, "cart must be JSON")
    items = cart.get("items", []) if isinstance(cart, dict) else []
    return {"items": len(items)}
```

If the cart has to survive a round trip through the client and come back
unchanged, sign it (Flask's own session cookie does this with JSON and
`itsdangerous`) and still never unpickle it. Do not add an `object_hook` that
builds arbitrary classes from the JSON either: that brings the same problem
back.

## Related

- [Insecure deserialization in Python](https://eyalsec.com/vulnerabilities/insecure-deserialization)
- [Code injection in Python](https://eyalsec.com/vulnerabilities/code-injection)
