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

- SQL injection
- Command injection
- Path traversal
- Insecure deserialization
- Server-side code injection (`exec` / `eval`)
- ...and more

It has already flagged two critical CVEs in Django.

## How it differs from static analysis

A static scanner reads your source before it runs and guesses at possible bugs.
`es-python` watches your program as it really runs and only reports untrusted
data that actually reaches a risky action, so it finds real, exploitable issues
with far fewer false positives, and can block them at runtime.

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
