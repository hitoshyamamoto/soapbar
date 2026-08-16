"""Django + soapbar: the same calculator on a Django WSGI stack.

Django's URL dispatcher speaks ``HttpRequest``/``HttpResponse``, not raw WSGI
callables, so the SOAP endpoint is mounted one layer *below* it: a small
composite WSGI app sends ``/soap`` to ``WsgiSoapApp`` and everything else to
Django. That keeps the SOAP POST out of Django's middleware chain — no CSRF
token, no session lookup — while the service class stays byte-identical to the
FastAPI and Flask versions.

Everything a Django project normally spreads across ``settings.py``,
``urls.py`` and ``wsgi.py`` is inlined via ``settings.configure()`` so the
example remains a single runnable file. In a real project: keep the
``SoapApplication`` in an app module and wrap the ``application`` object your
``wsgi.py`` already exports.

Run:
    uv add django
    uv run python examples/01_calculator/server_django.py

Endpoints:
    GET  http://127.0.0.1:8001/            → Django view (Django still serves)
    GET  http://127.0.0.1:8001/soap?wsdl   → WSDL
    POST http://127.0.0.1:8001/soap        → SOAP 1.1
"""
from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.utils import get_random_secret_key

# Django reads settings lazily, but they must exist before the WSGI handler is
# built — hence configure() ahead of get_wsgi_application() below.
settings.configure(
    DEBUG=False,
    ALLOWED_HOSTS=["127.0.0.1"],
    ROOT_URLCONF=__name__,  # urlpatterns lives in this module
    SECRET_KEY=get_random_secret_key(),
    INSTALLED_APPS=[],  # no ORM, no admin, no templates needed
    MIDDLEWARE=[],
)

from django.core.wsgi import get_wsgi_application  # noqa: E402
from django.http import HttpRequest, HttpResponse  # noqa: E402
from django.urls import path  # noqa: E402

from soapbar.server.application import SoapApplication  # noqa: E402
from soapbar.server.service import SoapService, soap_operation  # noqa: E402
from soapbar.server.wsgi import WsgiSoapApp  # noqa: E402


class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"

    @soap_operation(documentation="Add two integers")
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation(documentation="Subtract b from a")
    def subtract(self, a: int, b: int) -> int:
        return a - b

    @soap_operation(documentation="Multiply two integers")
    def multiply(self, a: int, b: int) -> int:
        return a * b

    @soap_operation(documentation="Divide a by b; b == 0 raises a SOAP fault")
    def divide(self, a: int, b: int) -> float:
        return a / b


def index(request: HttpRequest) -> HttpResponse:
    return HttpResponse("Django here. SOAP service: /soap?wsdl\n", content_type="text/plain")


urlpatterns = [path("", index)]

soap_app = SoapApplication(service_url="http://127.0.0.1:8001/soap")
soap_app.register(Calculator())

django_app = get_wsgi_application()
soap_wsgi = WsgiSoapApp(soap_app)


def application(environ: dict[str, Any], start_response: Any) -> Any:
    """Dispatch ``/soap`` to soapbar, everything else to Django.

    ``WsgiSoapApp`` keys off the request method and query string rather than the
    path, so mounting it is a prefix test — no rewriting of ``PATH_INFO``.
    """
    path_info = environ.get("PATH_INFO", "")
    if path_info == "/soap" or path_info.startswith("/soap/"):
        return soap_wsgi(environ, start_response)
    return django_app(environ, start_response)


if __name__ == "__main__":
    # wsgiref keeps the example dependency-free; point gunicorn/uWSGI at
    # ``application`` for anything real.
    from wsgiref.simple_server import make_server

    with make_server("127.0.0.1", 8001, application) as httpd:
        httpd.serve_forever()
