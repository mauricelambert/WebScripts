# API

## URLs

 - `/api/`: JSON response with scripts and arguments
 - `/api/scripts/<script name>`: JSON response with script *stdout* (outputs), *stderr* (errors) and *exitcode*. A *csrf token* is added if you use the WEB interface.

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

For web broswer:
```json
{
	"stdout": "<script outputs>", 
	"stderr": "<script  errors>", 
	"code": 0, 
	"Content-Type": "text/<plain or html>", 
	"csrf": "<token>", 
	"error": "<server timeout error>"
}
```

For client API:
```json
{
	"stdout": "<script outputs>", 
	"stderr": "<script  errors>", 
	"code": 0, 
	"Content-Type": "text/<plain or html>", 
	"error": "<server timeout error>"
}
```

### Request

For web broswer:
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
