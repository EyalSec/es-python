# SQL injection through Django's raw()

Django's ORM binds values for you, and that is why most Django code is safe
from SQL injection. `raw()` and `extra()` are the documented exceptions: they
take SQL text. This walkthrough shows a lookup that formats a request value
into `raw()`, what `es-python` reports, and the fix.

The code is [`django_raw_sql.py`](django_raw_sql.py): a whole Django project in
one file, with the vulnerable view and the fixed one side by side.

## The vulnerable view

```python
def find_customer(request):
    name = request.GET.get("name", "")
    rows = Customer.objects.raw(
        f"SELECT id, name, email FROM customer WHERE name = '{name}'"
    )
    return JsonResponse([{"name": c.name, "email": c.email} for c in rows], safe=False)
```

## Run it under es-python

You need Django installed for the same Python version
(`es-python -m pip install django`). A new machine already watches network
input (**socket**); check it is **On** in the machine's **Configure** window.

```bash
es-python django_raw_sql.py
curl --get http://127.0.0.1:8000/customers --data-urlencode "name=ada"
curl --get http://127.0.0.1:8000/customers --data-urlencode "name=x' OR '1'='1"
```

The second request returns every customer.

## What es-python reports

The event has the sink label `sql raw`, the impact tag `sqli` and the severity
**Critical**. Its **What this means** block reads:

> **What happened:** `Django QuerySet.raw() / QuerySet.extra()`: Data that came
> in over the network was used to build a database query.
>
> **Why this is risky:** An attacker who can send data to this program over the
> network may use this SQL injection to read or change any data in the
> database, and get past checks such as who may see which row.
>
> **What to do:** Use placeholders (`?` or `%s`) and pass the value as a
> parameter rather than joining strings or f-strings, so the database always
> treats it as data.

The sentence names two calls because one check covers both. You may also see a
`sqlite execute` row for the same request: Django hands the statement to the
database driver, and that call is checked too. With PostgreSQL or MySQL the
companion row carries that driver's label instead. Each block of evidence is
described in [Event detail](https://eyalsec.com/docs/event-detail).

## The fix

```python
def find_customer_fixed(request):
    name = request.GET.get("name", "")
    rows = Customer.objects.filter(name=name)
    return JsonResponse([{"name": c.name, "email": c.email} for c in rows], safe=False)
```

When you do need SQL text, pass the values separately:
`Customer.objects.raw("SELECT ... WHERE name = %s", [name])`. Either way the
request data never becomes part of the statement, and the same request to
`/customers-fixed` returns nothing and reports nothing.

## Related

- [SQL injection in Python](https://eyalsec.com/vulnerabilities/sql-injection)
- [Securing a Django app against SQL injection](https://eyalsec.com/research/securing-a-django-app-against-sql-injection)
- [The Block backend network attacks rule template](https://eyalsec.com/docs/rule-templates#block-backend),
  which blocks query text built from a request, `sql raw` included
