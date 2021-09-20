# Add Module

## Build the module

Write in `./scripts/py/hello.py`:
```python
def hello(environ, user, configuration, filename, arguments, inputs, csrf_token=None):
    return "200 OK", {"Content-Type": "text/plain"}, f"Hello {user.name} !"

def page_500(error):
    return error, {"Content-Type": "text/html; charset=utf-8"}, [b"<h1>ERROR 500</h1><br><br>\n\n", error.encode()]

def page_401(error):
    return error, {"Content-Type": "text/html; charset=utf-8"}, [b"<h1>ERROR 401</h1><br><br>\n\n", error.encode()]

def page_403(error):
    return error, {"Content-Type": "text/html; charset=utf-8"}, [b"<h1>ERROR 403</h1><br><br>\n\n", error.encode()]

def page_404(error):
    return error, {"Content-Type": "text/html; charset=utf-8"}, [b"<h1>ERROR 404</h1><br><br>\n\n", error.encode()]

```

## Add configuration

In a *server configuration file* in `server` section (using `INI` syntax):
```ini
modules=hello
modules_path=./scripts/py
```

## Load configurations
Restart the server.

## Get the pages
Open your web browser on `http://127.0.0.1:8000/hello/hello/`.
To test custom page for error 404: `http://127.0.0.1:8000/hello/`.
To test custom page for error 403: `http://127.0.0.1:8000/api/scripts/view_users.py`.
To test custom page for error 500: `http://127.0.0.1:8000/get/`.
