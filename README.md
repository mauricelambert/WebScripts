![WebScripts Logo](https://mauricelambert.github.io/info/python/code/WebScripts/small_logo.png)

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
[![Compatibility](https://img.shields.io/badge/compatibility-python3.8-orange)](https://webscripts.readthedocs.io/en/latest/Installation/#python38)
[![Containers](https://img.shields.io/badge/containers-docker-orange)](https://github.com/mauricelambert/WebScriptsContainers)

## Description
This tools run scripts and display the result in a Web Interface.

## Goals
Create a safe, secure and easy way to share console scripts and scripting environnments with your team or people without IT knowledge.

 - Secure
    - [SAST - Static Application Security Testing](https://webscripts.readthedocs.io/en/latest/Code_Analysis_for_Security/#sast-alerts) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security)) using [bandit](https://mauricelambert.github.io/info/python/code/WebScripts/bandit.txt), semgrep, CodeQL and Pycharm Security.
    - [DAST - Dynamic Application Security Testing](https://webscripts.readthedocs.io/en/latest/Code_Analysis_for_Security/#dast-alerts) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security)) using [ZAP](https://mauricelambert.github.io/info/python/code/WebScripts/ZAP.html) [(Baseline && full scan)](https://github.com/mauricelambert/WebScripts/issues/4), nuclei and some Kali Linux tools.
    - [Web pentest](https://webscripts.readthedocs.io/en/latest/Pentest/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Pentest)) using Kali Linux Web tools and my little experience in Web Hacking. Tools are [skipfish](https://mauricelambert.github.io/info/python/code/WebScripts/skipfish/index.html), [nikto](https://mauricelambert.github.io/info/python/code/WebScripts/nikto.html), [dirb](https://mauricelambert.github.io/info/python/code/WebScripts/dirb.txt) and [whatweb](https://mauricelambert.github.io/info/python/code/WebScripts/whatweb.json).
    - [Hardening](https://webscripts.readthedocs.io/en/latest/Development_and_Administration_Tools/#hardening-audit)([wiki](https://github.com/mauricelambert/WebScripts/wiki/Development-and-Administration-Tools#hardening-audit)), the WebScripts installation is pre-hardened, an audit is performed at the launch of the WebScripts server and reports are generated. Defaults/examples HTML reports: 
        - [Linux HTML report](https://mauricelambert.github.io/info/python/code/WebScripts/audit_linux.html), 
        - [Windows HTML report](https://mauricelambert.github.io/info/python/code/WebScripts/audit_windows.html), 
        - [docker with Apache and mod_wsgi HTML report](https://mauricelambert.github.io/info/python/code/WebScripts/docker_apache_audit.html), 
        - [docker with Nginx as HTTPS proxy HTML report](https://mauricelambert.github.io/info/python/code/WebScripts/docker_nginx_audit.html), 
        - [docker HTML report](https://mauricelambert.github.io/info/python/code/WebScripts/docker_audit.html)
    - Centralization of logs (using Syslog on Linux and Event Viewer on Windows)
    - Easy to update and patch security issues on Linux (critical functions are implemented in Standard Library and are updated with your system) (WebScripts does not require any python package)
    - Easy to deploy securely
        - [Docker with Apache and mod_wsgi](https://hub.docker.com/r/mauricelambert/webscripts) ([github](https://github.com/mauricelambert/WebScriptsContainers))
        - [Docker with Nginx as HTTPS proxy](https://hub.docker.com/r/mauricelambert/webscripts) ([github](https://github.com/mauricelambert/WebScriptsContainers))
        - [Docker](https://hub.docker.com/r/mauricelambert/webscripts) ([github](https://github.com/mauricelambert/WebScriptsContainers))
        - [Apache and mod_wsgi](https://webscripts.readthedocs.io/en/latest/Deployment/#apache-using-wsgi-mod) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment#apache-using-wsgi-mod))
        - [Nginx as HTTPS proxy](https://webscripts.readthedocs.io/en/latest/Deployment/#nginx-as-a-proxy-https) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment#nginx---as-a-proxy-https))
    - Easy to configure securely [(read the documentation)](https://webscripts.readthedocs.io/en/latest/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/))
        - INI/CFG syntax
        - JSON syntax
    - [Unittest](https://webscripts.readthedocs.io/en/latest/Development_and_Administration_Tools/#unittest) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Development-and-Administration-Tools#unittest))
        - ubuntu && python [3.8, 3.9, 3.10]
        - windows && python [3.8, 3.9, 3.10]
        - MacOS && python [3.8, 3.9, 3.10]
 - Customizable
    - [Authentication](https://webscripts.readthedocs.io/en/latest/Authentication/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Authentication)) - [example](https://webscripts.readthedocs.io/en/latest/Add_Script/#build-the-script) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Add-Script#build-the-script))
    - Web Interface: HTML, CSS and JS [files](https://webscripts.readthedocs.io/en/latest/WEB_Interface/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/WEB-Interface))
    - URL, request, response and error pages using [python modules](https://webscripts.readthedocs.io/en/latest/Modules/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Modules)) - [example](https://webscripts.readthedocs.io/en/latest/Add_Module/#build-the-module) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Add-Module))
 - Highly configurable and scalable
    - [Modules](https://webscripts.readthedocs.io/en/latest/Modules/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Modules))
    - Configurations: 
        - [server](https://webscripts.readthedocs.io/en/latest/Server_Configuration/#custom-configurations) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Server-Configuration#custom-configurations))
        - [scripts](https://webscripts.readthedocs.io/en/latest/Script_Configuration/#custom-configurations) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Script-Configuration#custom-configurations))
 - Pre-installed and configured scripts and modules
    - Account, [permissions](https://webscripts.readthedocs.io/en/latest/Users_Access_and_Rights/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Access-and-Permissions)) and [authentication system](https://webscripts.readthedocs.io/en/latest/Authentication/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Authentication))
    - [Share files](https://webscripts.readthedocs.io/en/latest/File_Share/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/File-Share)): upload and download files with permissions (example [here](https://webscripts.readthedocs.io/en/latest/API_Client/#upload-client), [wiki](https://github.com/mauricelambert/WebScripts/wiki/API-Client#upload-client))
    - HTTP Error Page Request and Reporting System
    - Temporary and secure password sharing
    - Logs viewer and analysis

## Demo

[![Demo WebScripts - Youtube](https://img.youtube.com/vi/2_hRBTRzl5w/0.jpg)](http://www.youtube.com/watch?v=2_hRBTRzl5w)

*Demonstration of WebScripts use - Youtube video*

## Requirements
This package require:

 - python3
 - python3 Standard Library

Optional on Windows:

 - pywin32 (to centralize logs in Event Viewer)

## Installation

```bash
pip install WebScripts --install-option "--admin-password=<your password>"
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

 - Home: [wiki](https://github.com/mauricelambert/WebScripts/wiki/), [readthedocs](https://webscripts.readthedocs.io/en/latest/)
 - Installation: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Installation), [readthedocs](https://webscripts.readthedocs.io/en/latest/Installation/)
 - Configurations:
    - Usages: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Usages), [readthedocs](https://webscripts.readthedocs.io/en/latest/Usages/)
    - Server Configurations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Server-Configuration), [readthedocs](https://webscripts.readthedocs.io/en/latest/Server_Configuration/)
    - Scripts Configurations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Script-Configuration), [readthedocs](https://webscripts.readthedocs.io/en/latest/Script_Configuration/)
    - Arguments Configurations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Argument-Configuration), [readthedocs](https://webscripts.readthedocs.io/en/latest/Argument_Configuration/)
 - Logs: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Logs), [readthedocs](https://webscripts.readthedocs.io/en/latest/Logs/)
 - Authentication: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Authentication), [readthedocs](https://webscripts.readthedocs.io/en/latest/Authentication/)
 - Default Database: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Default-Database), [readthedocs](https://webscripts.readthedocs.io/en/latest/Default_Database/)
 - Access and Permissions: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Access-and-Permissions), [readthedocs](https://webscripts.readthedocs.io/en/latest/Users_Access_and_Rights/)
 - API: [wiki](https://github.com/mauricelambert/WebScripts/wiki/API), [readthedocs](https://webscripts.readthedocs.io/en/latest/API/)
 - Development and Administration Tools: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Development-and-Administration-Tools), [readthedocs](https://webscripts.readthedocs.io/en/latest/Development_and_Administration_Tools/)
 - Customize:
    - WEB Interface: [wiki](https://github.com/mauricelambert/WebScripts/wiki/WEB-Interface), [readthedocs](https://webscripts.readthedocs.io/en/latest/WEB_Interface/)
    - Modules: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Modules), [readthedocs](https://webscripts.readthedocs.io/en/latest/Modules/)
 - Security:
    - Security Considerations: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Security-Considerations), [readthedocs](https://webscripts.readthedocs.io/en/latest/Security_Considerations/)
    - Code analysis for security (SAST and DAST): [wiki](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security), [readthedocs](https://webscripts.readthedocs.io/en/latest/Code_Analysis_for_Security/)
    - Security checks and tests (pentest): [wiki](https://github.com/mauricelambert/WebScripts/wiki/Pentest), [readthedocs](https://webscripts.readthedocs.io/en/latest/Pentest/)
 - Examples:
    - Deployment: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment), [readthedocs](https://webscripts.readthedocs.io/en/latest/Deployment/)
    - Add a bash script (for authentication): [wiki](https://github.com/mauricelambert/WebScripts/wiki/Add-Script), [readthedocs](https://webscripts.readthedocs.io/en/latest/Add_Script/)
    - Add a module: [wiki](https://github.com/mauricelambert/WebScripts/wiki/Add-Module), [readthedocs](https://webscripts.readthedocs.io/en/latest/Add_Module/)
    - Make a custom API client: [wiki](https://github.com/mauricelambert/WebScripts/wiki/API-Client), [readthedocs](https://webscripts.readthedocs.io/en/latest/API_Client/)

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
 - [Default module share](https://mauricelambert.github.io/info/python/code/WebScripts/share.html)

## Links

 - [Pypi](https://pypi.org/project/WebScripts)
 - [Github](https://github.com/mauricelambert/WebScripts)
 - [ReadTheDocs](https://webscripts.readthedocs.io/en/latest/)
 - RSS Feed [pypi](https://pypi.org/rss/project/webscripts/releases.xml), [libraries](https://libraries.io/pypi/WebScripts/versions.atom)

## Pictures

![Index page (dark)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_dark_mode_index.PNG "Index page (dark)")
*Index page (dark)*
![Text script (dark)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_dark_mode_script_text.PNG "Text script (dark)")
*Text script (dark)*
![HTML script (light)](https://mauricelambert.github.io/info/python/code/WebScripts/images/WebScripts_light_mode_script_html.PNG "HTML script (light)")
*HTML script (light)*

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
