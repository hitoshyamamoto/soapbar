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
| **Django** (≥ 3.1 ASGI) | Route in `asgi.py` via URL dispatcher |

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
| **Django** (classic WSGI) | Mount as sub-application in `urls.py` |
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
