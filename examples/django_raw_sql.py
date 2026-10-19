"""SQL injection through Django's QuerySet.raw(), and the fixed version beside it.

A whole Django project in one file. Deliberately vulnerable. Run it only on a
machine you are allowed to test.

    es-python django_raw_sql.py
    curl --get http://127.0.0.1:8000/customers       --data-urlencode "name=x' OR '1'='1"
    curl --get http://127.0.0.1:8000/customers-fixed --data-urlencode "name=x' OR '1'='1"

The first request returns every customer and is reported as `sql raw`.
The second returns nothing and is silent.
Walkthrough: django-raw-sql.md
"""
import os
import sys

import django
from django.conf import settings

settings.configure(
    DEBUG=False,
    SECRET_KEY="example-only-not-a-secret",
    ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=["127.0.0.1", "localhost"],
    INSTALLED_APPS=[],
    DATABASES={
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "customers.db"}
    },
    DEFAULT_AUTO_FIELD="django.db.models.AutoField",
)
django.setup()

from django.db import connection, models  # noqa: E402
from django.http import JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402


class Customer(models.Model):
    name = models.CharField(max_length=80)
    email = models.CharField(max_length=120)

    class Meta:
        app_label = "shop"
        db_table = "customer"


def init_db():
    if Customer._meta.db_table not in connection.introspection.table_names():
        with connection.schema_editor() as editor:
            editor.create_model(Customer)
    Customer.objects.all().delete()
    Customer.objects.create(name="ada", email="ada@example.com")
    Customer.objects.create(name="grace", email="grace@example.com")


def find_customer(request):
    name = request.GET.get("name", "")
    # VULNERABLE: raw() takes SQL text, and the name is formatted into it.
    rows = Customer.objects.raw(
        f"SELECT id, name, email FROM customer WHERE name = '{name}'"
    )
    return JsonResponse([{"name": c.name, "email": c.email} for c in rows], safe=False)


def find_customer_fixed(request):
    name = request.GET.get("name", "")
    # FIXED: the ORM binds the value. raw("... WHERE name = %s", [name]) is
    # equally safe when you do need SQL text.
    rows = Customer.objects.filter(name=name)
    return JsonResponse([{"name": c.name, "email": c.email} for c in rows], safe=False)


urlpatterns = [
    path("customers", find_customer),
    path("customers-fixed", find_customer_fixed),
]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    init_db()
    port = os.environ.get("PORT", "8000")
    execute_from_command_line([sys.argv[0], "runserver", f"127.0.0.1:{port}", "--noreload"])
