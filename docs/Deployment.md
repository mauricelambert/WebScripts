# Deployment

I propose two complete and secure deployment solutions:

 - WebScripts with Apache and mod_wsgi
 - WebScripts with Nginx as HTTPS proxy

## Deploy more easily and faster with docker

[![Deploy WebScripts - Youtube](https://img.youtube.com/vi/NhRpaRCNVVs/0.jpg)](http://www.youtube.com/watch?v=NhRpaRCNVVs)

*Deploy WebScripts - Youtube video*

 - Using [dockerhub](https://hub.docker.com/r/mauricelambert/webscripts)
 - Using [Dockerfile](https://github.com/mauricelambert/WebScriptsContainers)

Containers contain complete deployment solutions and are hardened.

## Python virtual environment

### Linux (Debian)

```bash
sudo apt update
sudo apt upgrade
sudo apt install python3-venv

python3 -m venv WebScripts        # Make a virtual environment for WebScripts
source WebScripts/bin/activate    # Activate your virtual environment
sudo WebScripts/bin/python3 -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=<owner>" --install-option "--directory=./WebScripts"     # Install WebScripts using setup.py with pip
sudo WebScripts/bin/python3 -m WebScripts.harden -p '<my admin password>' -o '<my webscripts user>' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

### Windows

```bash
python -m venv WebScripts        # Make a virtual environment for WebScripts
WebScripts/Scripts/activate    # Activate your virtual environment
WebScripts/Scripts/python -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--directory=.\WebScripts"     # Install WebScripts using setup.py with pip
WebScripts/Scripts/python -m WebScripts.harden -p '<my admin password>' -o '' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

## Web Server (Using Debian)

### NGINX - As a proxy HTTPS

#### WebScripts Service

```bash
useradd --system --no-create-home --shell /bin/false WebScripts

python3 -m venv WebScripts        # Make a virtual environment for WebScripts
source WebScripts/bin/activate    # Activate your virtual environment
sudo WebScripts/bin/python3 -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=WebScripts" --install-option "--directory=./WebScripts"     # Install WebScripts using setup.py with pip
sudo WebScripts/bin/python3 -m WebScripts.harden -p '<my admin password>' -o 'WebScripts' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)

nano /lib/systemd/system/WebScripts.service
```

```text
[Unit]
Description=The WebScripts Service (python service using HTTP protocol to run scripts from API or web interface).
Requires=network.target
After=network.target

[Service]
Type=simple
ExecStart=/path/to/virtualenv/bin/python3 -m WebScripts
Restart=always
StandardInput=tty-force
StandardOutput=inherit
User=WebScripts
UMask=077
WorkingDirectory=/path/to/virtualenv/

[Install]
WantedBy=multi-user.target
```

```bash
chown -R WebScripts:WebScripts /path/to/virtualenv/
sudo systemctl daemon-reload
sudo systemctl start WebScripts
sudo systemctl status WebScripts
```

#### Configure NGINX

```bash
sudo apt install nginx openssl
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out nginx.crt -keyout nginx.key
sudo systemctl enable nginx
sudo touch /etc/nginx/sites-available/WebScripts.conf
sudo ln -s /etc/nginx/sites-available/WebScripts.conf /etc/nginx/sites-enabled
sudo nano  /etc/nginx/sites-available/WebScripts.conf
```

```
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server { 
    listen 443 ssl; server_name kali;
    root /path/to/virtualenv/WebScripts;
    ssl_certificate     /path/to/certificat/nginx.crt;
    ssl_certificate_key /path/to/certificat/nginx.key;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8000;
    }
}
```

Add `WebScripts.conf` in `nginx.conf` (in *section* named `http`) and comment defaults configurations:

```bash
sudo nano /etc/nginx/nginx.conf
```

```text
include /etc/nginx/sites-available/WebScripts.conf;
# include /etc/nginx/sites-available/;
# include /etc/nginx/conf.d/*.conf;
```

Restart nginx:

```bash
sudo systemctl restart nginx
```

### Apache using WSGI mod

#### Install

```bash
sudo apt install libexpat1
sudo apt install apache2 apache2-utils ssl-cert libapache2-mod-wsgi-py3

sudo mkdir /var/www/WebScripts

python3 -m venv WebScripts        # Make a virtual environment for WebScripts
source WebScripts/bin/activate    # Activate your virtual environment
sudo WebScripts/bin/python3 -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=www-data" --install-option "--directory=/var/www/WebScripts/"     # Install WebScripts using setup.py with pip
sudo WebScripts/bin/python3 -m WebScripts.harden -p '<my admin password>' -o 'www-data' -d '/var/www/WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

#### Configure Apache

```bash
sudo chown www-data:www-data /path/to/virtualenv/bin/wsgi.py
sudo chmod 600 /path/to/virtualenv/bin/wsgi.py
sudo chown www-data:www-data /path/to/virtualenv/bin/activate_this.py
sudo chmod 600 /path/to/virtualenv/bin/activate_this.py

sudo touch /var/www/WebScripts/logs/apache-errors.logs
sudo touch /var/www/WebScripts/logs/apache-custom.logs
sudo touch /var/www/WebScripts/logs/root.logs

sudo apt install openssl
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out WebScripts.crt -keyout WebScripts.pem

sudo nano /etc/apache2/conf-available/wsgi.conf
```

```
<VirtualHost *:80>
    ServerName www.webscripts.com
    ServerAlias webscripts.com
    ServerAdmin admin@webscripts.com

    Redirect permanent / https://webscripts.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName www.webscripts.com
    ServerAlias webscripts.com
    ServerAdmin admin@webscripts.com

    WSGIScriptAlias / /path/to/virtualenv/bin/wsgi.py
    WSGIDaemonProcess webscripts.com processes=1 threads=15 display-name=%{GROUP}
    WSGIProcessGroup webscripts.com

    DocumentRoot /var/www/WebScripts
    DirectoryIndex index.html

    Alias /robots.txt /var/www/WebScripts/robots.txt
    Alias /favicon.ico /var/www/WebScripts/favicon.ico

    LogLevel info
    ErrorLog /var/www/WebScripts/logs/apache-errors.logs
    CustomLog /var/www/WebScripts/logs/apache-custom.logs combined

    SSLEngine on
    SSLCertificateFile /path/to/certificat/WebScripts.crt
    SSLCertificateKeyFile /path/to/certificat/WebScripts.pem

    <Directory /var/www/WebScripts>
        <IfVersion < 2.4>
            Order allow,deny
            Allow from all
        </IfVersion>
        <IfVersion >= 2.4>
            Require all granted
        </IfVersion>
    </Directory>
</VirtualHost>
```

```bash
sudo a2enconf wsgi
sudo a2enmod ssl
sudo systemctl reload apache2
sudo systemctl restart apache2
```

### Python Scripts used for Apache deployment

> The `bin/wsgi.py` script (preinstalled and configured by the WebScripts package):
>> This script can be customized (examples: to generate WebScripts configurations)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool runs CLI scripts and displays output in a Web Interface.
#    Copyright (C) 2021, 2022, 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This tool runs CLI scripts and displays output in a Web Interface.
"""

__version__ = "1.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = (
    "This tool runs CLI scripts and displays output in a Web Interface."
)
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

print(copyright)

from os.path import join, dirname
from typing import List
import atexit

activator = join(dirname(__file__), "activate_this.py")

with open(activator) as f:
    exec(f.read(), {"__file__": activator})  # nosec # nosemgrep

from WebScripts.WebScripts import (
    Server,
    configure_logs_system,
    send_mail,
    hardening,
    Logs,
    logger_debug,
    logger_info,
    logger_warning,
    prepare_server,
)


class Paths:

    """
    This class define configuration files.
    """

    def __init__(self, config_cfg: List[str], config_json: List[str]):
        self.config_cfg = config_cfg
        self.config_json = config_json


configure_logs_system()

paths = Paths([], [])

server, _ = prepare_server()

logger_debug("Trying to send email notification...")
send_mail(
    server.configuration, f"Server is up on http://{server.interface}:{server.port}/."
)

logger_debug("Configure email notification on server exit...")
atexit.register(
    send_mail,
    server.configuration,
    f"Server is down on http://{server.interface}:{server.port}/.",
)

logger_info("WebScripts server hardening audit...")
hardening(server)

logger_warning("Starting server...")
application = server.app
```

> The `bin/activate_this.py` script (preinstalled and configured by the WebScripts package):
>> You should not edit this file.

```python
"""By using execfile(this_file, dict(__file__=this_file)) you will
activate this virtualenv environment.

This can be used when you must use an existing Python interpreter, not
the virtualenv bin/python
"""

try:
    __file__
except NameError:
    raise AssertionError(
        "You must run this like execfile('path/to/active_this.py', dict(__file__='path/to/activate_this.py'))"
    )
import sys
import os

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
site_packages = os.path.join(
    base, "lib", "python%s" % ".".join(sys.version.split(".", 2)[:2]), "site-packages"
)
prev_sys_path = list(sys.path)
import site

site.addsitedir(site_packages)
sys.real_prefix = sys.prefix
sys.prefix = base
# Move the added items to the front of the path:
new_sys_path = []
for item in list(sys.path):
    if item not in prev_sys_path:
        new_sys_path.append(item)
        sys.path.remove(item)
sys.path[:0] = new_sys_path
```

