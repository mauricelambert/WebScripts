# WebScripts

[![PyPI version](https://badge.fury.io/py/WebScripts.svg)](https://badge.fury.io/py/WebScripts)
[![Downloads](https://static.pepy.tech/personalized-badge/webscripts?period=total&units=none&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/webscripts)

## Description
This package implements a web server to run scripts or executables from the command line and display the result in a web interface.

## Goals
Create a safe, secure and easy way to share console scripts and scripting environnments with your team or people without IT knowledge.
 - Secure
   - [SAST - Static Application Security Testing using bandit and semgrep](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security)
   - [Web pentest using Kali Linux Web tools and my little experience in Web Hacking](https://github.com/mauricelambert/WebScripts/wiki/Pentest)
   - Centralization of logs (using Syslog on Linux and Event Viewer on Windows)
   - Easy to update and patch security issues on Linux (critical functions are implemented in Standard Library and are updated with your system) (WebScripts does not require any python package)
   - Easy to deploy securely
     - [Apache and mod_wsgi](https://github.com/mauricelambert/WebScripts/wiki/Deployment#apache-using-wsgi-mod)
     - [Nginx as HTTPS proxy](https://github.com/mauricelambert/WebScripts/wiki/Deployment#nginx---as-a-proxy-https)
   - Easy to configure securely [(read the documentation)](https://github.com/mauricelambert/WebScripts/wiki/)
     - INI/CFG syntax
     - JSON syntax
   - [Unittest](#run-tests)

## Requirements
This package require:
 - python3
 - python3 Standard Library

Optional on Windows:
 - pywin32 (to centralize logs in Event Viewer)

## Installation

```bash
pip install WebScripts
```

## Basic Usages

### Command line

```bash
WebScripts
python3 -m WebScripts

WebScripts --help
WebScripts -h # Print help message and command line options

WebScripts --interface "192.168.1.2" --port 80
WebScripts -i "192.168.1.2" -p 80 # Change interface and port

# /!\ do not use the --debug option on the production environment
WebScripts --debug
WebScripts -d # Print informations about server configuration in errors pages (404 and 500)

# /!\ do not use the --security option on the production environment
WebScripts --security
WebScripts -s # Do not use HTTP security headers (for debugging)

WebScripts --accept-unauthenticated-user --accept-unknow-user
# Accept unauthenticated user
```

### Python script

```python
import WebScripts
WebScripts.main()
```

```python
from WebScripts import Configuration, Server, main
from wsgiref import simple_server

config = Configuration()
config.add_conf(
    interface="", 
    port=8000, 
    scripts_path = [
        "./scripts/account",
        "./scripts/passwords"
    ],
    json_scripts_config = [
        "./config/scripts/*.json"
    ],
    ini_scripts_config = [
        "./config/scripts/*.ini"
    ],
    documentations_path = [
        "./doc/*.html"
    ],
    js_path = [
        "./static/js/*.js"
    ],
    statics_path = [
        "./static/html/*.html",
        "./static/css/*.css",
        "./static/images/*.jpg",
        "./static/pdf/*.pdf"
    ],
)
config.set_defaults()
config.check_required()
config.get_unexpecteds()
config.build_types()

server = Server(config)
httpd = simple_server.make_server(server.interface, server.port, server.app)
httpd.serve_forever()
```

## Documentation

### Wiki
 - [Installation](https://github.com/mauricelambert/WebScripts/wiki/Installation)
 - [Usages](https://github.com/mauricelambert/WebScripts/wiki/Usages)
 - [Server Configuration](https://github.com/mauricelambert/WebScripts/wiki/Server-Configuration)
 - [Script Configuration](https://github.com/mauricelambert/WebScripts/wiki/Script-Configuration)
 - [Argument Configuration](https://github.com/mauricelambert/WebScripts/wiki/Argument-Configuration)
 - [Logs](https://github.com/mauricelambert/WebScripts/wiki/Logs)
 - [Authentication](https://github.com/mauricelambert/WebScripts/wiki/Authentication)
 - [Default Database](https://github.com/mauricelambert/WebScripts/wiki/Default-Database)
 - [Access and Permissions](https://github.com/mauricelambert/WebScripts/wiki/Access-and-Permissions)
 - [Security Considerations](https://github.com/mauricelambert/WebScripts/wiki/Security-Considerations)
 - [API](https://github.com/mauricelambert/WebScripts/wiki/API)
 - [Custom WEB Interface](https://github.com/mauricelambert/WebScripts/wiki/WEB-Interface)
 - [Modules (Custom responses and code)](https://github.com/mauricelambert/WebScripts/wiki/Modules)
 - [Code analysis for security (SAST)](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security)
 - [Security checks and tests (pentest tools)](https://github.com/mauricelambert/WebScripts/wiki/Pentest)

### Examples

 - [Deployment](https://github.com/mauricelambert/WebScripts/wiki/Deployment)
 - [Add a bash script (for authentication)](https://github.com/mauricelambert/WebScripts/wiki/Add-Script)
 - [Add a module](https://github.com/mauricelambert/WebScripts/wiki/Add-Module)
 - [Make a custom API client](https://github.com/mauricelambert/WebScripts/wiki/API-Client)

### PyDoc
 - [Index](https://mauricelambert.github.io/info/python/code/WebScripts/)
 - [WebScripts](https://mauricelambert.github.io/info/python/code/WebScripts/WebScripts.html)
 - [Pages](https://mauricelambert.github.io/info/python/code/WebScripts/Pages.html)
 - [commons](https://mauricelambert.github.io/info/python/code/WebScripts/commons.html)
 - [utils](https://mauricelambert.github.io/info/python/code/WebScripts/utils.html)
 - [Errors](https://mauricelambert.github.io/info/python/code/WebScripts/Errors.html)
 - [Default Database Manager](https://mauricelambert.github.io/info/python/code/WebScripts/manage_defaults_databases.html)
 - [Default Upload Manager](https://mauricelambert.github.io/info/python/code/WebScripts/uploads_management.html)
 - [Default Request Manager](https://mauricelambert.github.io/info/python/code/WebScripts/requests_management.html)
 - [Default module errors](https://mauricelambert.github.io/info/python/code/WebScripts/error_pages.html)

## Links
 - [Pypi](https://pypi.org/project/WebScripts)
 - [Github](https://github.com/mauricelambert/WebScripts)
 - [RSS feed](https://libraries.io/pypi/WebScripts/versions.atom)

## Pictures

![Index page (dark)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_dark_mode_index.JPG "Index page (dark)")
*Index page (dark)*
![Text script (dark)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_dark_mode_script_text.JPG "Text script (dark)")
*Text script (dark)*
![HTML script (light)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_light_mode_script_html.JPG "HTML script (light)")
*HTML script (light)*

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).

## Run tests

```bash
python -m unittest discover -s test -p Test*.py -v
```