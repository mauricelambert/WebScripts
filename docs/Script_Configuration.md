# Script Configuration

The configuration of the script is presented in this file, in the `WebScripts` project these files return an error because the *arguments section* is required. For more information on configuring arguments [click here](https://webscripts.readthedocs.io/en/latest/Argument_Configuration/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Argument-Configuration)).

## Using a specific file

To configure a script you can use a specific file.
In the main file for configuration (JSON syntax first and second with INI syntax):

```json
{
    "scripts": {
        "change_my_password.py": "config_change_my_password"
    },

    "config_change_my_password": {
        "configuration_file": "./config/files/change_my_password.json"
    },
}
```

```ini
[scripts]
change_my_password.py=config_change_my_password                                                # Define the configuration section ("change_my_password.py") for script named "config_change_my_password"

[config_change_my_password]
configuration_file=./config/files/change_my_password.json                                      # Define script configuration in a specific file
```

1. Create a `scripts` section
2. Define the *script name* and the *script section name* to configure the script (`change_my_password.py=config_change_my_password`)
3. Create the *script section* (in this example: `config_change_my_password`)
4. Define the name of the specific file (`configuration_file=./config/files/change_my_password.json`)

The specific file content (with JSON syntax):

```json
{
    "script": {
        "launcher": "python",
        "minimum_access": 50,
        "category": "My Account",
        "args": "change_my_password_args",
        "description": "This script can change your own password (for all authenticated users).",
        "command_generate_documentation": "python \"%(dirname)s/../doc/py_doc.py\" \"%(path)s\""
    }
}
```

1. Create the `script` section (the content is the *script configuration*)
2. Add your configurations

## Using the main file

1. Create a `scripts` section
2. Define the *script name* and the *script section name*
3. Create the *script section*
4. Add your configurations

JSON example:

```json
{
    "scripts": {
        "delete_user.py": "config_delete_user"
    },

    "config_delete_user": {
        "timeout": null,
        "access_users": [],
        "no_password": true,
        "launcher": "python",
        "access_groups": [1000],
        "content_type": "text/plain",
        "category": "Administration",
        "args": "config_delete_user_args",
        "documentation_content_type": "text/html",
        "path": "./scripts/account/delete_user.py",
        "documentation_file": "./doc/delete_user.html",
        "description": "This script delete user from ID.",
        "command_generate_documentation": "python \"%(dirname)s/../doc/py_doc.py\" \"%(path)s\""
    }
}
```

In this configuration:


   - *Admin* users can access it only (group ID 1000 is a default group named *Admin*)
   - A user in group ID 1001 and not in group ID 1000 can't access it (group ID is the permission level)

INI example:

```ini
[scripts]
auth.py=config_auth                                                                            # Define the configuration section ("config_auth") for script named "auth.py"

[config_auth]
launcher=python                                                                                # Define the launcher for this script (if script is executable this line is not necessary)
no_password=false                                                                              # If no_password is true the command line will be written to the logs
path=./scripts/account/auth.py                                                                 # Only necessary if the location of the script is not in "scripts_path"
documentation_file=./doc/auth.html                                                             # Only needed if the location of the documentation does not match the paths defined in "documentations_path"
content_type=text/plain                                                                        # Define the script output content-type (HTTP headers/javascript interpretation)
documentation_content_type=text/html                                                           # Define the documentation content-type
minimum_access=0                                                                               # If a user's group is greater than "minimum_access", the user can use this script
access_groups=0,1                                                                              # If a user's group is in "access_groups", the user can use this script
access_users=0,1,2                                                                             # If the user ID is in "access_users", the user can use this script
args=auth_args                                                                                 # The arguments are defined in section named "auth_args"
description=This script authenticates users.                                                   # Short description to help users
category=My Account                                                                            # Add a link on the index page in the "My Account" section
timeout=10                                                                                     # Timeout for process execution (in seconds)
command_generate_documentation=python "%(dirname)s/../doc/py_doc.py" "%(path)s"                # Command line to generate the documentation file
```

All users can access the authentication script, permissions are not used for this script (this is a simple example).
In this configuration:

   1. All users with a group greater than 0 can access this script
   2. All users in group 0 (group named *Not Authenticated*) or 1 (group named *Unknow*)
   3. Users with ID 0 (user named *Not Authenticated*) or ID 1 (user named *Unknow*) or ID 2 (user named *Admin*)

This configuration makes no sense because with `minimum_access=0` all user can access it, it's just an example.

## Configurations

 - `launcher`: executable to launch a script (not required and not necessary if the script is executable on **Linux**, on Windows the *WebScripts Server* search the default launcher for the file extension of the script)
 - `path`: the path of the script (absolute or relative path) (not required and not necessary if the script is in `scripts_path`, a server configuration)
 - `content_type`: The content type of *stdout* (script output) should be `text/html` or `text/plain` (not required, default is `text/plain`)
 - `minimum_access`: Define who can access it (view the *access* subtitle) (not required)
 - `access_groups`: Define who can access it (view the *access* subtitle) (not required)
 - `access_users`: Define who can access it (view the *access* subtitle) (not required)
 - `args`: Define the *arguments section name* (not required with no argument)
 - `description`: A short description to help users (not required)
 - `category`: To add a link on the index page (Web Interface), if not defined this script will be *hidden* in the web interface (not in API) (not required)
 - `timeout`: A timeout to kill the process execution of the script (not required)
 - `documentation_file`: documentation path and file name (absolute or relative path) (not required and not necessary if the documentation is in `documentations_path`, a server configuration)
 - `documentation_content_type`: The content type for documentation page (not required, default is `text/html`)
 - `command_generate_documentation`: A command to build the documentation file (not required)
 - `no_password`: If `no_password` is `true` the command line will be written to the logs (not required, default is `false`)
 - `stderr_content_type`: The content type of *stderr* (script erreurs) should be `text/plain` (not required, default is `text/plain`). Possible values: `text/plain` and `text/html`, for security reason you should never set the `stderr_content_type` to `text/html`.
 - `print_real_time`: the *stdout* (script output) is sent line after line (useful for long scripts and long output). Adding a few lines is **necessary** to use this configuration (flush the *stdout*, [examples](https://webscripts.readthedocs.io/en/latest/API_Client/#real-time-output) [wiki](https://github.com/mauricelambert/WebScripts/wiki/API-Client#using-python))

### Command to generate the documentation file

You can use all attributes of script configuration in this command. Script configuration contains all attributes defined in the configuration file and the `dirname` attribute (the absolute path without the filename).

Syntax: `%(<attribute>)s`.
Example: `python "%(dirname)s/../doc/py_doc.py" "%(path)s"`.

## Access

1. If `minimum_access`, `access_groups` and `access_users` is not defined **all users can access it**.
2. If `minimum_access` is defined all users with a *group ID and permissions* greater than `minimum_access` can access it.
3. If `access_groups` is defined all users with a *group ID and permissions* in `access_groups` can access it.
4. If `access_users` is defined all users with *user ID* in `access_users` can access it.

### Examples

All administraters (group ID: `1000`), the users with ID 5 and 7, all groups with ID greater than 1050 need to acces this script:
```json
{
    "access_groups": [1000],
    "access_users": [5, 7],
    "minimum_access": 1050
}
```

```ini
access_users=5,7
access_groups=1000
minimum_access=1050
```

## Recommendations

 - Use absolute path for launcher.
 - Use the `path` configuration and use absolute path.
 - Set the `no_password` configuration to `true` if no password is in the command-line arguments.
 - Set the `content_type` configuration to `text/plain` as often as possible.
 - Never use the `stderr_content_type` configuration.
 - Scripts should have the `timeout` configuration defined

## Custom configurations

You can add your custom configurations and get it in your script.
Be careful with custom configurations as they are sent to the `/api/` URL.
The `secrets` custom configuration is not sent in `/api/`.

### Example

In this example i add a key.

The configuration:
```json
{
    "scripts": {
        "example.py": "config_example"
    },

    "config_example": {
        "description": "Python executable file for the example configuration",
        "secrets": {
            "key": "azerty"
        },
        "web_interface_color": "orange"
    }
}
```

The python script:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import environ
from json import loads
config = loads(environ["SCRIPT_CONFIG"])
key = config["secrets"].get("key")
web_interface_color = config.get("web_interface_color")
```
