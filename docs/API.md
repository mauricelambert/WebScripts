# API

## URLs

 - `/api/` (**HTTP GET METHOD**): JSON response with scripts details/informations
 - `/api/scripts/<script name>` (**HTTP POST METHOD**): JSON response with script *stdout* (outputs), *stderr* (errors) and *exitcode*. A *csrf token* is added if you use the WEB interface.
 - `/api/script/get/<key>` (**HTTP GET METHOD**): JSON response 

## Structures

### Responses

#### Index

```json
{
	"<script name>": {
		"content_type": "text/<plain or html>", 
		"documentation_content_type": "text/<html or plain>", 
		"description": "<short description>", 
		"category": "<category>", 
		"name": "<script name>", 
		"args": [
			{
				"default_value": "<default value>", 
				"html_type": "<input type>", 
				"description": "<short description>", 
				"example": "<example>", 
				"input": false, 
				"predefined_values": ["<value1>", "<value2>"], 
				"list": false, 
				"name": "<argument name>"
			}
		]
	}
}
```

#### Script execution

```json
{
	"stdout": "<script outputs>", 
	"stderr": "<script  errors>", 
	"code": 0, 
	"Content-Type": "text/<plain or html>", 
	"csrf": "<token>", 
	"error": "<server timeout error>",
	"key": "<key>"
}
```

 - *stdout*: the output of the script. *Required*, type *string*.
 - *stderr*: script errors. *Required*, type *string*.
 - *code*: the exit code of the script. *Required*, type *integer* or *null*.
 - *Content-Type*: script output content-type. *Required*, type *string*, value: `text/plain` or `text/html`.
 - *Stderr-Content-Type*: script errors content-type. *Required*, type *string*, value: `text/plain` (**recommended for security reason**) or `text/html`.
 - *error*: WebScripts error (reason to kill the child process). *Required*, type *string*.
 - *key*: for *real time output* **only**, while *key* is defined the process is not terminated.
 - *csrf*: for *web browser* **only**, in the response of the *POST request* **only**.

### Request

#### Body - Content

A `POST` *HTTP method* is **required**. The content should be a JSON object with an `arguments` object as attribute (and a `csrf_token` string as attribute for *webbrowser*).

For web browser:
```json
{
	"csrf_token": "<token>",
	"arguments": {
		"<argument name>": {
			"value": "<value or list of values>",
			"input": false
		}
	}
}
```

For client API:
```json
{
	"arguments": {
		"<argument name>": {
			"value": "<value or list of values>",
			"input": false
		}
	}
}
```

#### Headers

Some *HTTP Headers* are **required** to use scripts with *WebScripts API*:

 - `Content-Type` should be `application/json` (or `application/json; charset=utf-8`).
 - `Origin` should be `<scheme>://<host>` (examples: `http://webscript.local`, `http://webscript.local:8000`, `https://webscript.local`, `https://webscript.local:4430`).
 - `Referer` should be the last visited page, **required for webbrowser only**.

Recommandation:

 - `Api-Token` should be the *session cookie* (example: `SessionID=2:0123456789abcdef`). Session cookie is sent by the server on the response of `/auth/` script (the `/auth/` script should accept `--username` and `--password` arguments **OR** `--api-key` argument). You can use `Api-Token` as much as you want but *Basic Auth* and `Api-Key` will be blacklisted if you exceed the anti bruteforce configuration.

## Authentication

To use the *WebScripts* API you can use HTTP **BasicAuth** or an *API key* in a `Api-Key` header.
You **should never** use these authentication methods with a *Web Browser* because CSRF protection is not enabled.

## Example of HTTP flux

### Authentication

#### Using Username and Password

Request **/auth/** to authenticate user using username and password:
```text
POST /auth/ HTTP/1.1
Accept-Encoding: identity
Content-Length: 115
Host: 127.0.0.1:8000
User-Agent: WebScripts client
Origin: http://127.0.0.1:8000
Content-Type: application/json
Connection: close

{"arguments": {"--username": {"value": "Admin", "input": false}, "--password": {"value": "Admin", "input": false}}}
```

Response:
```text
HTTP/1.0 302 Found
Date: Thu, 22 Jun 2016 02:43:52 GMT
Server: WebScripts 2.4.7
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Cache-Control: no-store
Pragma: no-store
Clear-Site-Data: "cache", "executionContexts"
Feature-Policy: payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'
Permissions-Policy: microphone=(),camera=(),payment=(),geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Server: WebScripts
Set-Cookie: SessionID=2:5c02e0ce9c3273ee5b19888cc13551396f429afd9a353c96eb693187e6f5364aeede55eb87dc14d70d938d96ff939e632282fd159fce48c4b16ddad3196c44e0; Path=/; SameSite=Strict; Max-Age=3600; Secure; HttpOnly
Content-Length: 0
```

#### Using API key

Request **/auth/** to authenticate user using API keu:
```text
POST /auth/ HTTP/1.1
Accept-Encoding: identity
Content-Length: 219
Host: 127.0.0.1:8000
User-Agent: WebScripts client
Origin: http://127.0.0.1:8000
Content-Type: application/json
Connection: close

{"arguments": {"--api-key": {"value": "AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin", "input": false}}}
```

Response:
```text
HTTP/1.0 302 Found
Date: Thu, 22 Jun 2016 05:09:45 GMT
Server: WebScripts 2.4.8
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Cache-Control: no-store
Pragma: no-store
Clear-Site-Data: "cache", "executionContexts"
Feature-Policy: payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'
Permissions-Policy: microphone=(),camera=(),payment=(),geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Server: WebScripts
Set-Cookie: SessionID=2:7de7040268fead766ebaa1dbf245568efb0cb14b51158cafd2e9e811a396135f96edacf55d144cb5abf4200fee53a070e12cb4cd8ed656ef8d2d488251364710; Path=/; SameSite=Strict; Max-Age=3600; Secure; HttpOnly
Content-Length: 0
```

### Execute script after authentication

Request script execution after authentication:
```text
POST /api/scripts/test_config.py HTTP/1.1
Accept-Encoding: identity
Content-Length: 433
Host: 127.0.0.1:8000
User-Agent: WebScripts client
Origin: http://127.0.0.1:8000
Api-Token: SessionID=2:5c02e0ce9c3273ee5b19888cc13551396f429afd9a353c96eb693187e6f5364aeede55eb87dc14d70d938d96ff939e632282fd159fce48c4b16ddad3196c44e0; Path=/; SameSite=Strict; Max-Age=3600; Secure; HttpOnly
Content-Type: application/json
Connection: close

{"arguments": {"select": {"value": "test", "input": false}, "--timeout": {"value": true, "input": false}, "password": {"value": ["Admin", "Admin"], "input": false}, "--test-date": {"value": "2016-06-22", "input": false}, "test_input": {"value": "abc", "input": false}, "test_number": {"value": 8.8, "input": false}, "test_file": {"value": "file content", "input": true}, "select-input": {"value": ["test", "select"], "input": true}}}
```

Response:
```text
HTTP/1.0 200 OK
Date: Thu, 22 Jun 2016 02:43:53 GMT
Server: WebScripts 2.4.7
Content-Type: application/json; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Cache-Control: no-store
Pragma: no-store
Clear-Site-Data: "cache", "executionContexts"
Feature-Policy: payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'
Permissions-Policy: microphone=(),camera=(),payment=(),geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Server: WebScripts
Content-Length: 191

{"stdout": "", "stderr": "", "code": null, "Content-Type": "text/plain", "Stderr-Content-Type": "text/plain", "error": null, "key": "EO0IhFUW2xoB-HgjQmvrGj8rpSzy6U6H-EWT9lnRgVBSO7r98brTaQ=="}
```

### Execute script with BasicAuth

Request script execution with BasicAuth:
```text
POST /api/scripts/test_config.py HTTP/1.1
Accept-Encoding: identity
Content-Length: 433
Host: 127.0.0.1:8000
User-Agent: WebScripts client
Origin: http://127.0.0.1:8000
Authorization: Basic QWRtaW46QWRtaW4=
Content-Type: application/json
Connection: close

{"arguments": {"select": {"value": "test", "input": false}, "--timeout": {"value": true, "input": false}, "password": {"value": ["Admin", "Admin"], "input": false}, "--test-date": {"value": "2016-06-22", "input": false}, "test_input": {"value": "abc", "input": false}, "test_number": {"value": 8.8, "input": false}, "test_file": {"value": "file content", "input": true}, "select-input": {"value": ["test", "select"], "input": true}}}
```

Response:
```text
HTTP/1.0 200 OK
Date: Thu, 22 Jun 2016 04:22:10 GMT
Server: WebScripts 2.4.7
Content-Type: application/json; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Cache-Control: no-store
Pragma: no-store
Clear-Site-Data: "cache", "executionContexts"
Feature-Policy: payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'
Permissions-Policy: microphone=(),camera=(),payment=(),geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Server: WebScripts
Content-Length: 191

{"stdout": "", "stderr": "", "code": null, "Content-Type": "text/plain", "Stderr-Content-Type": "text/plain", "error": null, "key": "DiJ_9fQSaAMaZGWFUtaAbl2DN5mbusiY69S3-4mXg2wd6jgxqIg8kg=="}
```

### Execute script with API Key

Request /api/ to get information about scripts and arguments with API key:
```text
GET /api/ HTTP/1.1
Accept-Encoding: identity
Host: 127.0.0.1:8000
User-Agent: WebScripts client
Origin: http://127.0.0.1:8000
Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin
Connection: close
```

Response:
```text
HTTP/1.0 200 OK
Date: Thu, 22 Jun 2016 05:09:12 GMT
Server: WebScripts 2.4.7
Content-Type: application/json; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Cache-Control: no-store
Pragma: no-store
Clear-Site-Data: "cache", "executionContexts"
Feature-Policy: payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'
Permissions-Policy: microphone=(),camera=(),payment=(),geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Server: WebScripts
Content-Length: 22610

{"/auth/": {"documentation_content_type": "text/html", "stderr_content_type": "text/plain", "content_type": "text/plain", "description": "This script authenticates users.", "category": "Authentication", "name": "/auth/", "args": [{"javascript_attributs": {}, "default_value": null, "is_advanced": false, "html_type": "text", "description": "Your username (to log in)", "example": "user", "input": false, "predefined_values": null, "list": false, "name": "--username"}, {"javascript_attributs": {}, "default_value": null, "is_advanced": false, "html_type": "password", "description": "Your password (to log in)", "example": "password", "input": null, "name": "--password"}]}}
```

### Request real time output

Request real time output:
```text
GET /api/script/get/GKUBELTPuZbF2GIWBFll1kojTnnp-eyrX5y1UgFEO2xRC7kGqPQg3g== HTTP/1.1
Accept-Encoding: identity
Host: 127.0.0.1:8000
User-Agent: WebScripts client
Origin: http://127.0.0.1:8000
Api-Token: SessionID=2:7de7040268fead766ebaa1dbf245568efb0cb14b51158cafd2e9e811a396135f96edacf55d144cb5abf4200fee53a070e12cb4cd8ed656ef8d2d488251364710; Path=/; SameSite=Strict; Max-Age=3600; Secure; HttpOnly
Connection: close
```

Response:
```text
HTTP/1.0 200 OK
Date: Thu, 22 Jun 2016 05:09:52 GMT
Server: WebScripts 2.4.8
Content-Type: application/json; charset=utf-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; form-action 'none'; frame-ancestors 'none'
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Cache-Control: no-store
Pragma: no-store
Clear-Site-Data: "cache", "executionContexts"
Feature-Policy: payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'
Permissions-Policy: microphone=(),camera=(),payment=(),geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Server: WebScripts
Content-Length: 206

{"stdout": "15 seconds...\r\n", "stderr": "", "code": null, "Content-Type": "text/plain", "Stderr-Content-Type": "text/plain", "error": "", "key": "GKUBELTPuZbF2GIWBFll1kojTnnp-eyrX5y1UgFEO2xRC7kGqPQg3g=="}
```
