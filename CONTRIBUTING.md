# Contributing

Thank you for taking the time. This repository is the public home and
documentation of an EyalSec product. It holds no product source, so it takes
**issues and documentation fixes, not code**. The reports you send are what
improve the product, and we read every one.

## What helps most

| You have | Do this |
|---|---|
| A flow that should have been reported and was not | Open a **Bug report** issue. A ten-line program that reproduces it is the most useful thing you can send. |
| An event you believe is wrong, or noisy | Open a **Bug report** issue with the event JSON. |
| A library, driver or operation you want covered | Open a **Feature request** issue. Say which call, and what untrusted data reaches it in your app. |
| A mistake in a README or an example | Open an issue, or a pull request that changes only Markdown or the files under `examples/`. |
| A question about using the product | Ask in [Discussions](../../discussions), or email support@eyalsec.com. |
| A security vulnerability in EyalSec itself | **Do not open an issue.** See [SECURITY.md](SECURITY.md). |
| A question about your plan or account | sales@eyalsec.com |

## Before you post: three things to leave out

Issues here are public.

1. **Credentials.** Never paste an install command (its token is a
   credential for ten minutes), an API key, a password or a session cookie.
2. **Other people's data.** An event carries the value that reached the
   operation, taken from your program's memory. Read the event JSON before you
   paste it, and replace anything personal or secret with `[redacted]`.
3. **Unfixed vulnerabilities in someone else's project.** If the product
   showed you a flaw in a third-party library, report it to that project
   privately first. Describe the shape here, not the exploit.

## A good bug report

The form asks for these. For es-python:

- the output of `es-python -V` and of `eyalsec info`;
- the distribution and architecture (`uname -m`, and the `ID` and `VERSION_ID`
  lines of `/etc/os-release`);
- which sources were on for the machine, and how the program was started;
- the smallest program that shows the problem;
- what you expected and what happened;
- the event JSON (`GET /api/event/{id}`, see the
  [API guide](https://eyalsec.com/docs/api-events#event-detail)), or the sink
  label and severity as the dashboard shows them.

Before filing "nothing is reported", run `eyalsec selftest` and read
[No events](https://eyalsec.com/docs/troubleshooting#no-events); it settles
most cases in a minute.

## What happens next

We reply on the issue. If we can reproduce it, we say so and label it; when a
release carries the fix, we close the issue and name the release in
[CHANGELOG.md](CHANGELOG.md). If we cannot reproduce it, we ask one question at
a time until we can. If we decide not to change something, we say why.

## Conduct

Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
