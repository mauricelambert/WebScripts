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
