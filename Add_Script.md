# Add Script

## Build the script

Write in `auth.sh`:

```bash
#!/bin/env bash

if [ $# -ne 2 ]
then
	echo 'USAGE: auth.sh <username> <password>'
	exit 1
fi

if [ "${1}" == "Admin" ] && [ "${2}" == "Admin" ]
then
	echo "{\"ip\":\"${X_REAL_IP}\",\"id\":\"2\",\"name\":\"Admin\",\"groups\":\"50,1000\"}"
else
	echo "{\"ip\":\"${X_REAL_IP}\",\"id\":\"0\",\"name\":\"Not Authenticated\",\"groups\":\"0\"}"
fi

exit 0
```

## Add configuration

### Specific configuration file

In a *main configuration file*:
```json
{
    "scripts": {
        "auth.sh": "config_auth"
    },

    "config_auth": {
        "configuration_file": "/path/to/configuration/file.json"
    }
}
```

In the *specific configuration file* (named `/path/to/configuration/file.json`):
```json
{
	"script": {
		"launcher": "bash",
		"category": "Authentication",
		"args": "auth_args",
		"description": "Authentication script."
	},

	"auth_args": {
		"username": "arg_username",
		"password": "arg_password"
	},

	"arg_username": {
		"example": "username",
		"html_type": "password",
		"description": "Your username"
	},

	"arg_password": {
		"example": "password",
		"html_type": "password",
		"description": "Your password"
	}
}
```

### Main configuration file

In a *main configuration file*:
```json
{
    "scripts": {
        "auth.sh": "config_auth"
    },

    "config_auth": {
		"launcher": "bash",
		"category": "Authentication",
		"args": "auth_args",
		"description": "Authentication script."
	},

	"auth_args": {
		"username": "arg_username",
		"password": "arg_password"
	},

	"arg_username": {
		"example": "username",
		"html_type": "password",
		"description": "Your username"
	},

	"arg_password": {
		"example": "password",
		"html_type": "password",
		"description": "Your password"
	}
}
```

## Load configuration

Restart the server.
