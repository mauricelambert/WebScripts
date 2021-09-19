![PyPI](https://img.shields.io/pypi/v/WebScripts?color=orange)
[![Downloads](https://static.pepy.tech/personalized-badge/webscripts?period=total&units=international_system&left_color=grey&right_color=orange&left_text=Downloads)](https://pepy.tech/project/webscripts)
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

# WebScripts

## Description
This package implements a web server to run scripts or executables from the command line and display the result in a web interface.

## Goals
Create a safe, secure and easy way to share console scripts and scripting environnments with your team or people without IT knowledge.
 - Secure
   - [SAST - Static Application Security Testing](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security) using [bandit](https://mauricelambert.github.io/info/python/code/WebScripts/bandit.txt), semgrep, CodeQL and Pycharm Security.
   - [DAST - Dynamic Application Security Testing](https://github.com/mauricelambert/WebScripts/wiki/Code-Analysis-for-Security) using [ZAP](https://mauricelambert.github.io/info/python/code/WebScripts/ZAP.html) [(Baseline && full scan)](https://github.com/mauricelambert/WebScripts/issues/4), nuclei and some Kali Linux tools.
   - [Web pentest](https://github.com/mauricelambert/WebScripts/wiki/Pentest) using Kali Linux Web tools and my little experience in Web Hacking. Tools are [skipfish](https://mauricelambert.github.io/info/python/code/WebScripts/skipfish/index.html), [nikto](https://mauricelambert.github.io/info/python/code/WebScripts/nikto.html), [dirb](https://mauricelambert.github.io/info/python/code/WebScripts/dirb.txt) and [whatwheb](https://mauricelambert.github.io/info/python/code/WebScripts/whatweb.json).
   - Centralization of logs (using Syslog on Linux and Event Viewer on Windows)
   - Easy to update and patch security issues on Linux (critical functions are implemented in Standard Library and are updated with your system) (WebScripts does not require any python package)
   - Easy to deploy securely
     - [Apache and mod_wsgi](https://github.com/mauricelambert/WebScripts/wiki/Deployment#apache-using-wsgi-mod)
     - [Nginx as HTTPS proxy](https://github.com/mauricelambert/WebScripts/wiki/Deployment#nginx---as-a-proxy-https)
   - Easy to configure securely [(read the documentation)](https://github.com/mauricelambert/WebScripts/wiki/)
     - INI/CFG syntax
     - JSON syntax
   - [Unittest](https://github.com/mauricelambert/WebScripts/wiki/Development-and-Administration-Tools#unittest)

# Installation

## Requirements
This package require:
 - python3
 - python3 Standard Library

Optional on Windows:
 - pywin32 (to centralize logs in Event Viewer)

## Linux

```bash
python3 -m pip install WebScripts
```

## Windows

```bash
python -m pip install WebScripts
```

### Optional

To centralize logs in Event Viewer.
```bash
python -m pip install pywin32
```

## Start the server

You can now start the server with this simple command:
```bash
WebScripts
```

## First connection

To log in for the first time, use the `Admin` account (username: `Admin`, password: `Admin`). I recommend changing the password **immediately**. The `Admin` account is restricted on `127.0.*,192.168.*,172.16.*,10.*` by default.

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
