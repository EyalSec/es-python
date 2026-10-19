"""Server-side request forgery in a FastAPI endpoint, and the fixed version beside it.

Deliberately vulnerable. Run it only on a machine you are allowed to test.

    es-python -m pip install fastapi uvicorn
    es-python fastapi_ssrf.py
    curl --get http://127.0.0.1:8000/preview       --data-urlencode "url=http://127.0.0.1:8000/internal/status"
    curl --get http://127.0.0.1:8000/preview-fixed --data-urlencode "url=http://127.0.0.1:8000/internal/status"

The first request makes the server fetch its own internal page for the caller
and is reported as `ssrf`. The second is refused with a 400 before any
connection is opened.
Walkthrough: fastapi-ssrf.md
"""
import ipaddress
import os
import socket
import urllib.request
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException

app = FastAPI()


@app.get("/internal/status")
def internal_status():
    # Stands in for a service that is only meant to be reachable from inside.
    return {"queue_depth": 3, "note": "internal only"}


@app.get("/preview")
def preview(url: str):
    # VULNERABLE: the server connects wherever the caller says.
    with urllib.request.urlopen(url, timeout=5) as resp:
        return {"status": resp.status, "body": resp.read(300).decode("utf-8", "replace")}


def _public_http_url(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 80)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@app.get("/preview-fixed")
def preview_fixed(url: str):
    # FIXED: http(s) only, every resolved address must be public, no redirects.
    # In production an egress proxy with an allowlist is stronger still: it
    # also closes the gap between this check and the connection.
    if not _public_http_url(url):
        raise HTTPException(status_code=400, detail="url must be a public http(s) address")
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=5) as resp:
        return {"status": resp.status, "body": resp.read(300).decode("utf-8", "replace")}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
