# Framework compatibility

## ASGI frameworks (via `AsgiSoapApp`)

`AsgiSoapApp` is a standard ASGI application. Mount it anywhere an ASGI app is accepted.

| Framework | How to mount |
|---|---|
| **FastAPI** | `app.mount("/soap", AsgiSoapApp(soap_app))` |
| **Starlette** | `routes=[Mount("/soap", app=AsgiSoapApp(soap_app))]` |
| **Litestar** | `app.mount("/soap", AsgiSoapApp(soap_app))` |
| **Quart** | Use `asgiref` or serve directly with Hypercorn |
| **BlackSheep** | `app.mount("/soap", AsgiSoapApp(soap_app))` |
| **Django** (≥ 3.1 ASGI) | Wrap the `application` object in `asgi.py`, dispatching on `scope["path"]` (same shape as the WSGI example below) |

ASGI servers (Uvicorn, Hypercorn, Daphne) can run `AsgiSoapApp` directly.

**FastAPI example:**

```python
from fastapi import FastAPI
from soapbar import SoapApplication, AsgiSoapApp

soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

api = FastAPI()
api.mount("/soap", AsgiSoapApp(soap_app))
```

## WSGI frameworks (via `WsgiSoapApp`)

| Framework | How to mount |
|---|---|
| **Flask** | `DispatcherMiddleware` or replace `app.wsgi_app` (requires `werkzeug`) |
| **Django** (classic WSGI) | Wrap the `application` object in `wsgi.py`, dispatching on `PATH_INFO` |
| **Falcon** | `app.add_sink(WsgiSoapApp(soap_app), "/soap")` |
| **Bottle** | `app.mount("/soap", WsgiSoapApp(soap_app))` |
| **Pyramid** | Composable WSGI stack |

WSGI servers (Gunicorn, uWSGI, mod_wsgi) can run `WsgiSoapApp` directly.

**Flask example:**

```python
from flask import Flask
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from soapbar import SoapApplication, WsgiSoapApp

soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

flask_app = Flask(__name__)
flask_app.wsgi_app = DispatcherMiddleware(flask_app.wsgi_app, {
    "/soap": WsgiSoapApp(soap_app),
})
```

**Django example:**

Django's URL dispatcher routes to views that take an `HttpRequest`, so a raw WSGI
callable cannot be mounted in `urls.py`. Wrap the `application` object your `wsgi.py`
already exports instead:

```python
# wsgi.py
import os

from django.core.wsgi import get_wsgi_application
from soapbar import SoapApplication, WsgiSoapApp

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

soap_app = SoapApplication(service_url="https://example.com/soap")
soap_app.register(CalculatorService())

_django_app = get_wsgi_application()
_soap_wsgi = WsgiSoapApp(soap_app)


def application(environ, start_response):
    path_info = environ.get("PATH_INFO", "")
    if path_info == "/soap" or path_info.startswith("/soap/"):
        return _soap_wsgi(environ, start_response)
    return _django_app(environ, start_response)
```

Dispatching one layer *below* Django keeps the SOAP POST out of the middleware chain —
no CSRF token, no session lookup — while the service class stays identical to the
FastAPI and Flask versions. `WsgiSoapApp` keys off the request method and query string
rather than the path, so mounting it is a prefix test with no `PATH_INFO` rewriting.

A runnable single-file version, covered by the example smoke tests, is in
[`examples/01_calculator/server_django.py`](https://github.com/hitoshyamamoto/soapbar/blob/main/examples/01_calculator/server_django.py).
