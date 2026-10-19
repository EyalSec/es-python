# SSRF in a FastAPI endpoint

A "link preview" endpoint fetches whatever URL the caller sends. From outside,
an attacker cannot reach your internal services; through this endpoint the
server reaches them on the attacker's behalf. This walkthrough shows the
endpoint, what `es-python` reports, and the fix.

The code is [`fastapi_ssrf.py`](fastapi_ssrf.py), with the vulnerable route and
the fixed one side by side.

## The vulnerable route

```python
@app.get("/preview")
def preview(url: str):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return {"status": resp.status, "body": resp.read(300).decode("utf-8", "replace")}
```

## Run it under es-python

```bash
es-python -m pip install fastapi uvicorn
es-python fastapi_ssrf.py
curl --get http://127.0.0.1:8000/preview \
  --data-urlencode "url=http://127.0.0.1:8000/internal/status"
```

A new machine already watches network input (**socket**); check it is **On**
in the machine's **Configure** window. The request makes the server fetch its
own `/internal/status` page, which stands in for a service only meant to be
reachable from inside, and hands the body back to the caller.

## What es-python reports

The check is made on the address the program actually dials, not on the string
that was submitted. Every outbound connection built from untrusted data gives a
base event (`socket connect`, `socket getaddrinfo`). When the destination is a
loopback, link-local or private-range address, as here, an `ssrf` event fires
alongside it, with the impact tag `ssrf` and the severity **Critical**. Its
**What this means** block reads:

> **What happened:** `socket.connect() / socket.getaddrinfo() /
> socket.gethostbyname()`: Data that came in over the network was used as the
> address this program opens a connection to.
>
> **Why this is risky:** An attacker who can send data to this program over the
> network may use this server-side request forgery (SSRF) to make the program
> connect to an address they choose, including internal services that are not
> reachable from outside.
>
> **What to do:** Decide where to connect yourself: check the host against a
> list you control, and reject loopback, link-local (`169.254.*`) and private
> addresses.

Because the destination is what is checked, an internal hostname and a redirect
from an allowed host to a forbidden one both still count. Each block of
evidence is described in [Event detail](https://eyalsec.com/docs/event-detail).

## The fix

Allow only `http` and `https`, resolve the host, reject every private,
loopback, link-local and reserved address, and do not follow redirects:

```python
@app.get("/preview-fixed")
def preview_fixed(url: str):
    if not _public_http_url(url):
        raise HTTPException(status_code=400, detail="url must be a public http(s) address")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=5) as resp:
        return {"status": resp.status, "body": resp.read(300).decode("utf-8", "replace")}
```

The same request to `/preview-fixed` is refused with a 400 before any
connection is opened. A fetch to a public address still gives the base
`socket connect` event, on purpose: the address is still the caller's choice.
A [Hide rule](https://eyalsec.com/docs/rules) keeps it out of your list once
you have reviewed it. In production, an egress proxy with an allowlist is
stronger than a check at each call site.

## Related

- [SSRF in Python](https://eyalsec.com/vulnerabilities/ssrf)
- [SSRF in Python services](https://eyalsec.com/research/ssrf-in-python-services)
- [The Block backend network attacks rule template](https://eyalsec.com/docs/rule-templates#block-backend)
