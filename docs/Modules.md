# Modules

Module is useful to send custom response:

 - Custom headers
 - Custom dynamic page
 - Custom URL
 - Custom request (POST form, custom JSON content...)
 - Custom authentication and permissions
 - ...

Module is a python file or a *package* imported in *WebScripts Server*.

## Custom functions

Signature:

```python
from typing import TypeVar, List, Dict, Tuple, Union
from collections.abc import Iterator
from os import _Environ

Json = TypeVar("Json", dict, list, str, int, None)
ServerConfiguration = TypeVar("ServerConfiguration")
User = TypeVar("User")

def example1(
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        arguments: List[str],       # Arguments is a list of str, if you send a "WebScripts request" (a JSON object with "arguments" as attribute)
        inputs: List[str],          # Value of inputs
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[str, bytes, Iterator[bytes]]]:

    return (
        "200 OK",
        {"Content-Security-Policy": "default-src 'self'"},
        "Response text."
    )

def example2(
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        arguments: Json,            # Arguments is a loaded JSON, if you send a JSON content without attribute named "arguments" 
        inputs: List[str],          # Inputs will be a empty list
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[str, bytes, Iterator[bytes]]]:

        return (
                "200 OK",
                {"Content-Security-Policy": "default-src 'self'"},
                [b"Response text."]
        )

def example3(
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        arguments: bytes,           # Arguments is bytes, if you send a non JSON request
        inputs: List[str],          # Inputs will be a empty list
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[str, bytes, Iterator[bytes]]]:

        return (
                "200 OK",
                {"Content-Security-Policy": "default-src 'self'"},
                (x for x in [b"Response text."])
        )
```

### Arguments

 1. `environ` (no default value): WSGI environment variables for this request
 2. `user` (no default value): User object (attributes: `["id", "name", "groups", "csrf", "ip", "check_csrf"]`
, optional: *your custom user configurations*)
 3. `server_configuration` (no default value): Server configurations (attributes: `["interface", "port", "debug", "security", "active_auth", "auth_script", "accept_unknow_user", "accept_unauthenticated_user", "modules", "modules_path", "js_path", "statics_path", "documentations_path", "scripts_path", "json_scripts_config", "ini_scripts_config", "log_level", "log_filename", "log_level", "log_format", "log_date_format", "log_encoding", "auth_failures_to_blacklist", "blacklist_time"]`)
 4. `filename` (no default value): element after the last `/`
 5. `arguments` (no default value): list of command line arguments (to launch a *script*) or a loaded JSON (JSON content without "arguments" attribute) or bytes (non-JSON content)
 6. `inputs` (no default value): list of inputs (for *stdin* of the script) or empty list (if the content is a non WebScripts request: non-JSON content or JSON without "arguments" attribute)
 7. `csrf_token` (optional: default value is `None`)

The `arguments` and `inputs` lists are built if you respect the default JSON body of *WebScripts Server*. If the body of the request is JSON without `arguments` *key*/*attribute*, `arguments` will be a *dict* or *list*. If the body of the request is not JSON, `arguments` will be *bytes*.

### Return

 1. Response `HTTP code` (`str`): the HTTP status of the response, the first three digits are required (example: `200 OK`)
 2. `Headers` (`dict`): dictionary of HTTP headers (pairs of names and header values)
 3. Response body (`bytes`, `str`, `Iterator[bytes]`): the HTTP body of the response

## URLs

In the `PATH_INFO` the character `/` is like `.` (object attribute) in python code, the last `/` is a *call* (`function()`).

### Examples

URLs to call a function named `hello` in a `hello` module:
```
/hello/hello/                   # python code equivalent: hello.hello(..., filename='', ...)
/hello/hello/abc                # python code equivalent: hello.hello(..., filename='abc', ...)
```

URLs to call a function named `test` in a class named `Test` in a module named `Tests` in a package named `Example`:
```
/Example/Tests/Test/test/       # python code equivalent: Example.Tests.Test.test(..., filename='', ...)
/Example/Tests/Test/test/abc    # python code equivalent: Example.Tests.Test.test(..., filename='abc', ...)
```

## Headers

Some default security headers are sended for all response, you can change the value but you can't delete these headers.

## Custom error pages

To build your custom error pages (HTTP errors: 500, 403, 404...) create a module (the name does not matter) with functions named: `page_<error>`, for example on error 500 the function used will be `page_500`.

Look at `/path/of/WebScripts/scripts/py/hello.py` this is a demonstration.

## Try

To try a module you can comment/uncomment lines (16-19) in `server.ini`, to get the following configuration:

```ini
# modules                                                                                        # Add custom modules (names) to the server
# modules_path                                                                                   # Add directory to import custom modules
modules=hello
modules_path=./scripts/py
```

Start the *WebScripts Server* and open these URL in your web broswer:

 1. [Hello function](http://127.0.0.1:8000/hello/hello/).
 2. [Custom error 500 page](http://127.0.0.1:8000/hello/) (only if the `debug` configuration is `false`).
 3. [Custom error 404 page](http://127.0.0.1:8000/hello/test/) (only if the `debug` configuration is `false`).
 4. Custom error 403 page

Get the code in `/path/of/WebScripts/project/scripts/py/hello.py`. 

## Default modules

 - `cgi`, make your own web pages and responses with any executable files and scripts
 - `Configuration`, activated with the *debug mode*, read and change your configurations in the web page without stop and restart the WebScripts server.
 - `csp`, activated with the *debug mode*, debug the CSP errors and get the CSP report.
 - `error_pages`, default error pages with requests to WebScripts administrators.
 - `JsonRpc`, a simple *json rpc* module to add simple API for some of your automatised tasks
 - `notification`, add a notifcation on the WebScripts Web Page
 - `rss`, a RSS to notify, read and add news for teams
 - `share`, uploads files and generates links to download shared files

### Examples

#### CGI

##### Simple

URL: http://127.0.0.1:8000/cgi/bin/test.py, http://127.0.0.1:8000/cgi/test.py, http://127.0.0.1:8000/bin/test.py, http://127.0.0.1:8000/cgi-bin/test.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

print("Content-Type: text/plain")
print()
print("Hello world !")
```

##### Advanced

URL: http://127.0.0.1:8000/cgi/bin/hello.py, http://127.0.0.1:8000/cgi/hello.py, http://127.0.0.1:8000/bin/hello.py, http://127.0.0.1:8000/cgi-bin/hello.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cgi import FieldStorage, parse, MiniFieldStorage
from urllib.parse import unquote, parse_qs

# from cgitb import enable
from os import environ
from sys import argv

# enable() # debug mode


def parse_args(*args, **kwargs) -> None:

    """
    This function parses arguments/body with
    differents functions/tools.
    """

    print("\t\t - Simple parsing:")
    if len(argv) == 2:
        arguments = unquote(argv[1])
        print(f"\t\t\t - Arguments: {argv[0]!r} {argv[1]!r}")
    else:
        arguments = parse_qs(
            environ["QUERY_STRING"], *args, **kwargs
        ) or parse(*args, **kwargs)
        for key, values in arguments.items():
            print(
                "\t\t\t - ",
                repr(key),
                "=",
                *[(repr(v) + ", ") for v in values],
            )

    print("\t\t - Complex parsing:")
    arguments = FieldStorage(*args, **kwargs)
    for argument_name in arguments.keys():
        value = arguments[argument_name]
        if isinstance(value, MiniFieldStorage):
            print(
                "\t\t\t - ",
                repr(argument_name),
                "=",
                repr(value.value) + ",",
                value,
            )
        elif isinstance(value, list):
            print(
                "\t\t\t - ",
                repr(argument_name),
                "=",
                [(repr(v.value) + ",") for v in value],
                *value,
            )


print("Content-Type: text/plain")
print()
print("Hello world !")

print("\t 1. Don't keep blank values: ")
parse_args()
print("\t 2. Keep blank values: ")
parse_args(keep_blank_values=True)

print("- WebScripts -")
```

#### CSP

Only with insecure mode activated, **don't use it in production**.

URL: http://127.0.0.1:8000/csp/debug/

#### Configurations

Only with debug mode activated, **don't use it in production**.

URL: http://127.0.0.1:8000/Configurations/Reload/server/, http://127.0.0.1:8000/Configurations/Reload/scripts/[script_name] (http://127.0.0.1:8000/Configurations/Reload/scripts/test_config.py), http://127.0.0.1:8000/Configurations/Reload/arguments/[script_name]|[argument_name] (http://127.0.0.1:8000/Configurations/Reload/arguments/test_config.py|test_input), http://127.0.0.1:8000/Configurations/Reload/modules/, http://127.0.0.1:8000/Configurations/Reload/web/, http://127.0.0.1:8000/Configurations/Reload/module/[module_name] (http://127.0.0.1:8000/Configurations/Reload/module/cgi)

#### Error pages

URL: http://127.0.0.1:8000/error_pages/Report/new/[HTTP_error_code], http://127.0.0.1:8000/error_pages/Request/send/[HTTP_error_code]

Error pages are used when the body is *empty* or `None`:

```python
# create your default error page for error 404
def page_404(error: str) -> Tuple[str, Dict[str, str], List[bytes]]:
    """
    This function returns the default HTTP response for error 404.
    """
    return "404 Not Found" or error, {"Header1": "Value1"}, [b'<html><body>Error 404, Page Not Found, are you lost ?</body></html>']

def not_found_default(environ, user, server_configuration, filename, arguments, inputs, csrf_token = None):
    return "404", {}, None  # call page_404 because data is None

def not_found_default(environ, user, server_configuration, filename, arguments, inputs, csrf_token = None):
    return "404", {}, b''   # call page_404 because data is empty

def not_found_custom(environ, user, server_configuration, filename, arguments, inputs, csrf_token = None):
    return "404", {"Header1": "Value1"}, [b'html><body>This is not my default 404 error page !</body></html>'] # don't call page_404 because there are data
```

#### JsonRpc

##### Server

```python
from WebScripts.modules.JsonRpc import JsonRpc

def test_call() -> int:
    return 0

def test_argument_list(*args) -> str:
    return str([repr(a) for a in args])

def test_argument_dict(a:int = 1, b:int = 2) -> int:
    return a + b

JsonRpc.register_function(test_call, "call")
JsonRpc.register_function(test_argument_list)
JsonRpc.register_function(test_argument_dict, "test_args_dict")

# start your WebScripts server here
```

##### Client

URL: http://127.0.0.1:8000/JsonRpc/JsonRpc/call, http://127.0.0.1:8000/JsonRpc/JsonRpc/test_argument_list, http://127.0.0.1:8000/JsonRpc/JsonRpc/test_args_dict

```python
from urllib.request import urlopen, Request, HTTPError, URLError
from pprint import pprint
from json import load

try:
    response = urlopen(
        Request(
            "http://127.0.0.1:8000/JsonRpc/JsonRpc/call",
            method="POST",
            headers={"Origin": "http://127.0.0.1:8000", "Authorization": "Basic QWRtaW46QWRtaW4=", "Content-Type": "application/json"},
            data=b'{"jsonrpc": "2.0", "id": 1, "method": "call"}',
        )
    )
except (HTTPError, URLError) as e:
    response = e

print("Status", response.code, response.reason)
pprint(load(response))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/JsonRpc/JsonRpc/test_argument_list",
        method="POST",
        headers={"Origin": "http://127.0.0.1:8000", "Authorization": "Basic QWRtaW46QWRtaW4=", "Content-Type": "application/json"},
        data=b'{"jsonrpc": "2.0", "id": 2, "method": "test_argument_list", "params": ["abc", 1, null, true]}',
    )
)
pprint(load(response))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/JsonRpc/JsonRpc/test_args_dict",
        method="POST",
        headers={"Origin": "http://127.0.0.1:8000", "Authorization": "Basic QWRtaW46QWRtaW4=", "Content-Type": "application/json"},
        data=b'{"jsonrpc": "2.0", "id": 3, "method": "test_args_dict", "params": {"a": 2, "b": 3}}',
    )
)
pprint(load(response))
```

#### Notification

URL: http://127.0.0.1:8000/notification/add/

#### RSS

URL: http://127.0.0.1:8000/rss/Feed/csv/[news_category], http://127.0.0.1:8000/rss/Feed/json/[news_category], http://127.0.0.1:8000/rss/Feed/[news_category]

#### Share

URL: http://127.0.0.1:8000/share/Download/filename/LICENSE.txt, http://127.0.0.1:8000/share/Download/id/0, http://127.0.0.1:8000/share/upload/
