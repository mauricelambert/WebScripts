# WebScripts

![PyPI](https://img.shields.io/pypi/v/WebScripts?color=orange)
[![Downloads](https://static.pepy.tech/personalized-badge/webscripts?period=total&units=none&left_color=grey&right_color=orange&left_text=Downloads)](https://pepy.tech/project/webscripts)
![GitHub branch checks state](https://img.shields.io/github/checks-status/mauricelambert/WebScripts/main?color=orange)
![PyPI - Status](https://img.shields.io/pypi/status/WebScripts?color=orange)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/WebScripts?color=orange)
![GitHub commit activity](https://img.shields.io/github/commit-activity/y/mauricelambert/WebScripts?color=orange)
![GitHub top language](https://img.shields.io/github/languages/top/mauricelambert/WebScripts?color=orange)
![GitHub issues](https://img.shields.io/github/issues/mauricelambert/WebScripts?color=orange)
![GitHub closed issues](https://img.shields.io/github/issues-closed/mauricelambert/WebScripts?color=orange)
![GitHub](https://img.shields.io/github/license/mauricelambert/WebScripts?color=orange)
![GitHub repo size](https://img.shields.io/github/repo-size/mauricelambert/WebScripts?color=orange)
![Libraries.io SourceRank](https://img.shields.io/librariesio/sourcerank/pypi/webscripts?color=orange)
[![Compatibility](https://img.shields.io/badge/compatibility-python3.8-orange)](https://github.com/mauricelambert/WebScripts/wiki/Installation#python38)

## Description
This package implements a web server to run scripts or executables from the command line and display the result in a web interface.

## Goals
Create a safe, secure and easy way to share console scripts and scripting environnments with your team or people without IT knowledge.
 - Secure
   - [SAST - Static Application Security Testing](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security) using [bandit](https://mauricelambert.github.io/info/python/code/WebScripts/bandit.txt), semgrep, CodeQL and Pycharm Security.
   - [DAST - Dynamic Application Security Testing](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security) using [ZAP](https://mauricelambert.github.io/info/python/code/WebScripts/ZAP.html) [(Baseline && full scan)](https://github.com/mauricelambert/WebScripts/issues/4), nuclei and some Kali Linux tools.
   - [Web pentest](https://github.com/mauricelambert/WebScripts/wiki/Pentest) using Kali Linux Web tools and my little experience in Web Hacking. Tools are [skipfish](https://mauricelambert.github.io/info/python/code/WebScripts/skipfish/index.html), [nikto](https://mauricelambert.github.io/info/python/code/WebScripts/nikto.html), [dirb](https://mauricelambert.github.io/info/python/code/WebScripts/dirb.txt) and [whatweb](https://mauricelambert.github.io/info/python/code/WebScripts/whatweb.json).
   - Centralization of logs (using Syslog on Linux and Event Viewer on Windows)
   - Easy to update and patch security issues on Linux (critical functions are implemented in Standard Library and are updated with your system) (WebScripts does not require any python package)
   - Easy to deploy securely
     - [Apache and mod_wsgi](https://github.com/mauricelambert/WebScripts/wiki/Deployment#apache-using-wsgi-mod)
     - [Nginx as HTTPS proxy](https://github.com/mauricelambert/WebScripts/wiki/Deployment#nginx---as-a-proxy-https)
   - Easy to configure securely [(read the documentation)](https://github.com/mauricelambert/WebScripts/wiki/)
     - INI/CFG syntax
     - JSON syntax
   - [Unittest](https://github.com/mauricelambert/WebScripts/wiki/Development-and-Administration-Tools#unittest)

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

## Compatibility

### Python3.8

```bash
git clone https://github.com/mauricelambert/WebScripts.git
cd WebScripts
python3.8 WebScripts/scripts/to_3.8/to_3.8.py
python3.8 setup38.py install
python3.8 -m WebScripts38
```

```python
# Launch this commands line:
#   - git clone https://github.com/mauricelambert/WebScripts.git
#   - cd WebScripts
#   - python3.8 WebScripts/scripts/to_3.8/to_3.8.py
#   - python3.8 setup38.py install
# And use the package:

import WebScripts38
WebScripts38.main()
```

## Documentation

 - Home: [wiki](https://github.com/mauricelambert/WebScripts/wiki/)
 - Installation: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Installation)
 - Configurations:
   - Usages: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Usages)
   - Server Configurations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Server-Configuration)
   - Scripts Configurations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Script-Configuration)
   - Arguments Configurations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Argument-Configuration)
 - Logs: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Logs)
 - Authentication: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Authentication)
 - Default Database: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Default-Database)
 - Access and Permissions: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Access-and-Permissions)
 - API: [wiki](https://github.com/mauricelambert/WebScripts/wiki/API)
 - Development and Administration Tools: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Development-and-Administration-Tools)
 - Customize:
   - WEB Interface: [wiki](https://github.com/mauricelambert/WebScripts/wiki/WEB-Interface)
   - Modules: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Modules)
 - Security:
   - Security Considerations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Security-Considerations)
   - Code analysis for security (SAST and DAST): [wiki](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security)
   - Security checks and tests (pentest): [wiki](https://github.com/mauricelambert/WebScripts/wiki/Pentest)
 - Examples:
   - Deployment: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment)
   - Add a bash script (for authentication): [wiki](https://github.com/mauricelambert/WebScripts/wiki/Add-Script)
   - Add a module: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Add-Module)
   - Make a custom API client: [wiki](https://github.com/mauricelambert/WebScripts/wiki/API-Client)

### PyDoc
 - [\_\_init\_\_](https://mauricelambert.github.io/info/python/code/WebScripts/)
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
 - [RSS feed](https://pypi.org/rss/project/webscripts/releases.xml)

## Pictures

![Index page (dark)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_dark_mode_index.JPG "Index page (dark)")
*Index page (dark)*
![Text script (dark)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_dark_mode_script_text.JPG "Text script (dark)")
*Text script (dark)*
![HTML script (light)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_light_mode_script_html.JPG "HTML script (light)")
*HTML script (light)*

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
