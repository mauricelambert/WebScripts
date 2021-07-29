# Server Configuration

The server configuration is modified with default configuration files, custom configuration files and command line arguments.

Priority:
1. Command line arguments
2. Custom JSON files
3. Custom INI files
4. Default JSON file
5. Default INI file

The default configuration JSON files:
```json
{
    "server": {
        "interface": "127.0.0.1",
        "port": 8000,

        "debug": false,
        "security": true,
        "accept_unknow_user": false,
        "accept_unauthenticated_user": false,
        "active_auth": true,
        "auth_script": "auth.py",

        "scripts_path": ["./scripts/account", "./scripts/passwords"],
        "json_scripts_config": ["./config/scripts/*.json"],
        "ini_scripts_config": ["./config/scripts/*.ini"],
        "documentations_path": ["./doc/*.html"],
        "modules": null,
        "modules_path": null,
        "js_path": ["./static/js/*.js"],
        "statics_path": ["./static/html/*.html", "./static/css/*.css", "./static/images/*.jpg", "./static/pdf/*.pdf"],

        "log_level": "0",
        "log_filename": "./logs/logs.log",
        "log_format": "%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)",
        "log_date_format": "%d/%m/%Y %H:%M:%S",
        "log_encoding": "utf-8",

        "auth_failures_to_blacklist": 3,
        "blacklist_time": 30
    }
}
```

The default configuration INI file:
```ini
[server]
interface=127.0.0.1                                                                            # required value
port=8000                                                                                      # required value

debug=false                                                                                    # Export config and get error messages on HTTP errors pages [NEVER true in production]
security=true                                                                                  # Add security HTTP headers
accept_unknow_user=false                                                                       # Don't force a user to re-authenticate
accept_unauthenticated_user=false                                                              # Don't force authentication for new user
active_auth=true                                                                               # Active auth page
auth_script=auth.py                                                                            # Change it to use a custom authentication script

scripts_path=./scripts/account,./scripts/passwords                                             # Add scripts from location
json_scripts_config=./config/scripts/*.json                                                    # Add server configuration (syntax: json)
ini_scripts_config=./config/scripts/*.ini                                                      # Add server configuration (syntax: cfg, ini)
documentations_path=./doc/*.html                                                               # Add path to search documentation scripts
modules                                                                                        # Add custom modules (names) to the server
modules_path                                                                                   # Add directory to import custom modules
# modules=hello
# modules_path=./scripts/py
js_path=./static/js/*.js                                                                       # Add glob syntax files to get javascript files
statics_path=./static/html/*.html,./static/css/*.css,./static/images/*.jpg,./static/pdf/*.pdf  # Add glob syntax files to get static files

log_level=0                                                                                    # Set your custom log level {"0", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
log_filename=./logs/logs.log                                                                   # Write your custom logs in this filename
log_format=%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)     # Format for your custom logs (https://docs.python.org/3/library/logging.html#id2)
log_date_format=%d/%m/%Y %H:%M:%S                                                              # Format date for your custom logs (https://docs.python.org/3/library/time.html#time.strftime)
log_encoding=utf-8                                                                             # Encoding for your custom log file

auth_failures_to_blacklist=3                                                                   # Number of authentication failures to blacklist an IP address or user
blacklist_time=30                                                                              # Blacklist time in seconds
```

 - *interface*: to change the connection interface
 - *port*: to change the connection port
 - *debug*: active the debug mode (export configuration, print error message and existing URLs in web page)
 - *security*: send security HTTP headers
 - *accept_unknow_user* and *accept_unknow_user*: don't force client authentication
 - *active_auth*: active the authentication script
 - *auth_script*: filename for the authentication script
 - *scripts_path*: paths to research a script (if not defined in script configuration)
 - *json_scripts_config*: **glob syntax** to get JSON files
 - *statics_path*: **glob syntax** to get static files (HTML files, CSS files, pictures, PDF files, text files...)
 - *log_level*: Log level for *ROOT* logger (impact **all** loggers, recommended value: "0")
 - *log_filename*: log filename for *ROOT* logger (impact *ROOT* logger only)
 - *log_format*: log format for *ROOT* logger (impact *ROOT* logger only), [references](https://docs.python.org/3/library/logging.html#id2)
 - *log_date_format*: date format for logs (impact *ROOT* logger only), [references](https://docs.python.org/3/library/time.html#time.strftime)
 - *log_encoding*: encoding for log file (impact *ROOT* logger only, recommended value: "utf-8")
 - *auth_failures_to_blacklist*: Number of authentication failures to blacklist an IP address or user
 - *blacklist_time*: Time in seconds to blacklist an IP address or user

## INI syntax

### List

To build a list in *INI* files, use `,`.

Example:
```ini
list=value1,value2,value3
```

### Boolean

To build a list in *INI* files, use `true` or `false`.

Example:
```ini
booleanTrue=true
booleanFalse=false
```
