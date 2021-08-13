# Authentication

The authentication script should follow certain rules.

## Requirements

### Command line arguments

Usages should contain a similar message:
```text
USAGES:
	authentication --api-key [APIKEY required string]
	authentication --username [USERNAME required string] --password [PASSWORD required string]
```

To authenticate a API client the *WebScripts Server* call the authentication script with `--api-key` argument or `--username` and `--password` arguments.

### Output (STDOUT)

Output must be an user object as JSON syntax.
Attribute required are:
 - `ip`: the IP address of the client
 - `id`: the **unique ID** of the client 
 - `name`: the name of the client
 - `groups`: the list of group IDs (group ID must be **unique**), the list can use the JSON syntax: `[50, 1000]` or the INI syntax: `"50,1000"`
 - `categories`: list of glob syntax for authorized categories
 - `scripts`: list of glob syntax for authorized scripts

Sample python code to follow all requirements:
```python
from json import dumps
from os import environ

ip = environ.get("X_REAL_IP")
    or environ.get("X_FORWARDED_FOR")
    or environ.get("X_FORWARDED_HOST")
    or environ["REMOTE_ADDR"]

print(
        json.dumps(
            {
                "id": "0",
                "name": "Not Authenticated",
                "ip": ip,
                "groups": "0",
                "categories": ["*"],
                "scripts": ["*"]
            }
        )
    )
```

If authentication fails your script should print the JSON for the *Not Authenticated* user (like the previous example).

## Custom user attributes

You can add attributes in the JSON output, they will be added in the user object and you can get them in your scripts.
Output example:
```json
{
    "id": 0,
    "name": "Admin",
    "ip": "127.0.0.1",
    "groups": [50, 1000],
    "passwords_key": "key_to_decrypt_my_passwords"
}
```

Sample python code:
```python
from json import loads
from os import environ

passwords_key = loads(environ["USER"]).get("passwords_key")
```
