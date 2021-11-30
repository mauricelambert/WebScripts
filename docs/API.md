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

## Authentication

To use the *WebScripts* API you can use HTTP **BasicAuth** or an *API key* in a `Api-Key` header.
You **should never** use these authentication methods with a *Web Browser* because CSRF protection is not enabled.
