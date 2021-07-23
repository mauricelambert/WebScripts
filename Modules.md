# Modules

Module is useful to send custom response:
 - Custom headers
 - Custom dynamic page
 - Custom URL
 - Custom authentication and permissions
 - ...

Module is a python file or a *package* imported in *WebScripts Server*.

## Custom functions

Signature:
```python
def example(
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

	return (
		"200 OK",
		{"Content-Security-Policy": "default-src 'self'"},
		"Response text."
	)
```

### Arguments

 1. `environ` (no default value): WSGI environment variables for this request
 2. `user` (no default value): User object (attributes: `["id", "name", "groups", "csrf", "ip", "check_csrf"]`
, optional: *your custom user configurations*)
 3. `server_configuration` (no default value): Server configurations (attributes: `["interface", "port", "debug", "security", "active_auth", "auth_script", "accept_unknow_user", "accept_unauthenticated_user", "modules", "modules_path", "js_path", "statics_path", "documentations_path", "scripts_path", "json_scripts_config", "ini_scripts_config", "log_level", "log_filename", "log_level", "log_format", "log_date_format", "log_encoding", "auth_failures_to_blacklist", "blacklist_time"]`)
 4. `filename` (no default value): element after the last `/`
 5. `arguments` (no default value): list of command line arguments (to launch a *script*)
 6. `inputs` (no default value): list of inputs (for *script stdin*)
 7. `csrf_token` (optional: default value is `None`)

The `arguments` and `inputs` lists are built from the JSON body with the *WebScripts Server* body parser, you must respect the default JSON syntax.

### Return

 1. `Response code`: the HTTP status of the response, the first three digits are required (example: `200 OK`)
 2. `Headers`: dictionary of HTTP headers (pairs of names and header values)
 3. `Response body`: the HTTP body of the response

## URLs

In the `PATH_INFO` the character `/` is like `.` (object attribute) in python code, the last `/` is a *call* (`()`).

### Examples

URLs to call a function named `hello` in a `hello` module:
```
/hello/hello/                   # python code equivalent: hello.hello(), filename argument: ''
/hello/hello/abc                # python code equivalent: hello.hello(), filename argument: 'abc'
```

URLs to call a function named `test` in a class named `Test` in a module named `Tests` in a package named `Example`:
```
/Example/Tests/Test/test/       # python code equivalent: Example.Tests.Test.test(), filename argument: ''
/Example/Tests/Test/test/abc    # python code equivalent: Example.Tests.Test.test(), filename argument: 'abc'
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
