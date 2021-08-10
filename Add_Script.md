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

## Using uploads in python script

Sometimes you need to use a file uploaded to the WebScripts server in your python script or write a file and find it in the WebScripts uploads.

```python
from WebScripts.scripts.uploads.modules.uploads_management import (
    Upload, 
    get_file, 
    read_file, 
    write_file, 
    delete_file, 
    get_file_content, 
    get_visible_files,
)
from base64 import b64decode, b64encode

write_file(
    "\x00string content\xff", # if is binary you can use base64 ou decode it with latin-1
    "my_filename.txt",        # File name
    0,                        # Read access (0 == everyone can read it)
    0,                        # Write access (0 == everyone can write it)
    0,                        # Delete access (0 == everyone can delete it)
    False,                    # Hidden (if False, this file will be visible to other authenticated users)
    False,                    # Is binary
    False,                    # Is encoded as Base64
    with_access = True,       # Check access to write this file (some scripts should write a file with an unauthenticated user)
)                             # Write a new file named "my_filename.txt"

content2 = b64encode(b'\x00version 2\xff').decode()

filenames: List[str] = []
for file in get_visible_files():
    assert isinstance(file, Upload)
    filenames.append(file.name)

assert "my_filename.txt" in filenames
# file is not hidden and not deleted

write_file(
    content2,                 # if is binary you can use base64 ou decode it with latin-1
    "my_filename.txt",        # File name
    0,                        # Read access (0 == everyone can read it)
    1000,                     # Write access (1000 == Admin can write it)
    1000,                     # Delete access (1000 == Admin can delete it)
    True,                     # Hidden
    True,                     # Is binary
    True,                     # Is encoded as Base64
    with_access = False,      # Check access to write this file (some scripts should write a file with an unauthenticated user)
)                             # Write a new version of this file

filenames: List[str] = []
for file in get_visible_files():
    filenames.append(file.name)

assert "my_filename.txt" not in filenames
# file is hidden

versions, counter = get_file("my_filename.txt")
assert len(versions) == 2

assert b64decode(read_file("my_filename.txt").encode()) == b"\x00version 2\xff"
# read_file check access

data, filename = get_file_content(name="my_filename.txt")
assert b64decode(data.encode()) == b"\x00version 2\xff"
# get_file_content don't check access

delete_file("my_filename.txt")

try:
    get_file_content(name="my_filename.txt")
    read_file("my_filename.txt")
except FileNotFoundError:
    pass
# a deleted file can't be read using the filename

data, filename = get_file_content(id_="1")
assert b64decode(data.encode()) == b"\x00string content\xff"
# get_file_content can read an old version (and deleted file)
```