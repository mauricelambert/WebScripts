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
        "auth_failures_to_blacklist": 3,
        "blacklist_time": 30,
        "exclude_auth_paths": ["/static/", "/js/"],
        "exclude_auth_pages": ["/api/", "/auth/", "/web/auth/"],

        "scripts_path": [
            "./scripts/account", 
            "./scripts/passwords", 
            "./scripts/uploads"
        ],
        "json_scripts_config": [
            "./config/scripts/*.json"
        ],
        "ini_scripts_config": [
            "./config/scripts/*.ini"
        ],
        "documentations_path": [
            "./doc/*.html"
        ],
        "modules": ["error_pages"],
        "modules_path": ["./modules"],
        "js_path": [
            "./static/js/*.js"
        ],
        "statics_path": [
            "./static/html/*.html", 
            "./static/css/*.css", 
            "./static/images/*.png", 
            "./static/images/*.jpg", 
            "./static/pdf/*.pdf"
        ],

        "log_level": "0",
        "log_filename": "./logs/root.logs",
        "log_format": "%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)",
        "log_date_format": "%d/%m/%Y %H:%M:%S",
        "log_encoding": "utf-8",

        "smtp_server": null,
        "smtp_starttls": false,
        "smtp_password": null,
        "smtp_port": 25,
        "smtp_ssl": false,
        "admin_adresses": [
            "admin1@webscripts.local",
            "admin2@webscripts.local"
        ],
        "notification_address": "notification@webscripts.local"
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
auth_failures_to_blacklist=3                                                                   # Number of authentication failures to blacklist an IP address or user
blacklist_time=30                                                                              # Blacklist time in seconds
exclude_auth_paths=/static/,/js/                                                               # Start of paths where the unauthenticated user gets access
exclude_auth_pages=/api/,/auth/,/web/auth/                                                     # Specific page where the unauthenticated user has access

scripts_path=./scripts/account,./scripts/passwords,./scripts/uploads                           # Add scripts from location
json_scripts_config=./config/scripts/*.json                                                    # Add server configuration (syntax: json)
ini_scripts_config=./config/scripts/*.ini                                                      # Add server configuration (syntax: cfg, ini)
documentations_path=./doc/*.html                                                               # Add path to search documentation scripts
# modules                                                                                      # Add custom modules (names) to the server
# modules_path                                                                                 # Add directory to import custom modules
modules=error_pages
modules_path=./modules
js_path=./static/js/*.js                                                                       # Add glob syntax files to get javascript files
statics_path=./static/html/*.html,./static/css/*.css,./static/images/*.png,./static/images/*.jpg,./static/pdf/*.pdf  # Add glob syntax files to get static files

log_level=DEBUG                                                                                # Set your custom log level {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
log_filename=./logs/root.logs                                                                  # Write your custom logs in this filename
log_format=%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)     # Format for your custom logs (https://docs.python.org/3/library/logging.html#id2)
log_date_format=%d/%m/%Y %H:%M:%S                                                              # Format date for your custom logs (https://docs.python.org/3/library/time.html#time.strftime)
log_encoding=utf-8                                                                             # Encoding for your custom log file

smtp_server                                                                                    # SMTP configuration is used to send notifications, the server name or the IP address of the SMTP server
smtp_starttls=false                                                                            # Using starttls to secure the connection
smtp_password                                                                                  # Password for email account (username is the notification_address configuration), if password is None the client send email without authentication
smtp_port=25                                                                                   # SMTP port
smtp_ssl=false                                                                                 # Using SSL (not starttls) to secure the connection
admin_adresses=admin1@webscripts.local,admin2@webscripts.local                                 # Administrators email addresses to receive the notification
notification_address=notification@webscripts.local                                             # Notification address to send the notification (the sender email address)
```

 - *interface*: to change the connection interface
 - *port*: to change the connection port
 - *debug*: active the debug mode (export configuration, print error message and existing URLs in web page)
 - *security*: send security HTTP headers, desactive the Content-Security-Policy-Report-Only header and debug module for Content-Security-Policy
 - *accept_unknow_user* and *accept_unauthenticated_user*: don't force client authentication
 - *active_auth*: active the authentication script
 - *auth_script*: filename for the authentication script
 - *auth_failures_to_blacklist*: Number of authentication failures to blacklist an IP address or user
 - *blacklist_time*: Time in seconds to blacklist an IP address or user
 - *exclude_auth_paths*: Start of paths where the unauthenticated user gets access
 - *exclude_auth_pages*: Specific page where the unauthenticated user has access
 - *scripts_path*: paths to research a script (if not defined in script configuration)
 - *ini_scripts_config*: **glob syntax** to research INI scripts configurations files
 - *json_scripts_config*: **glob syntax** to research JSON scripts configurations files
 - *documentations_path*: list of **glob syntax** to research documentation files
 - *modules*: list of names of custom modules
 - *js_path*: list of **glob syntax** to research javascripts files
 - *modules_path*: list of directories to import the modules
 - *statics_path*: **glob syntax** to get static files (HTML files, CSS files, pictures, PDF files, text files...)
 - *log_level*: Log level for *ROOT* logger (impact **all** loggers, recommended value: "0")
 - *log_filename*: log filename for *ROOT* logger (impact *ROOT* logger only)
 - *log_format*: log format for *ROOT* logger (impact *ROOT* logger only), [references](https://docs.python.org/3/library/logging.html#id2)
 - *log_date_format*: date format for logs (impact *ROOT* logger only), [references](https://docs.python.org/3/library/time.html#time.strftime)
 - *log_encoding*: encoding for log file (impact *ROOT* logger only, recommended value: "utf-8")
 - *smtp_server*: The SMTP server name to send email notifications (if it's `None` notifications will not be sent)
 - *smtp_starttls*: Use StartTLS to secure the connection
 - *smtp_password*: Login as `notification_address` configuration using this password. If it's `None` notifications will be sent without authentication.
 - *smtp_port*: The SMTP server port.
 - *smtp_ssl*: Use SSL to secure the connection
 - *admin_adresses*: Administrators email addresses to receive email notification
 - *notification_address*: Address to send email notifications (and username if password is not `None`)

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

## Custom configurations

You can had custom server configurations and use it in *modules*.

```json
{
    "server": {
        "interface": "127.0.0.1",
        "port": 8000,

        "custom_configuration": "My custom configuration !"
    }
}
```

With this configuration, the *server configuration object* will have a `custom_configuration` attribut set to `My custom configuration !`.

## Recommendation

 - `log_level` should be `0`.
 - `smtp_password` should only be used if `smtp_ssl` is set to `true` or `smtp_starttls` is set to `true`.
 - `blacklist_time` and `auth_failures_to_blacklist` configurations should be configured.
 - `active_auth` configuration should be set to `true`.
 - `accept_unknow_user` and `accept_unauthenticated_user` configurations should be set to `false`.
 - `exclude_auth_paths` configuration should be equal to `["/static/", "/js/"]`.
 - `exclude_auth_pages` configuration should be equal to `["/api/", "/auth/", "/web/auth/"]`.
 - `modules_path` configuration should be absolute paths
