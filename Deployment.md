# Deployment

## Python virtual environment

### Linux
```bash
sudo apt update
sudo apt upgrade
sudo apt install python3-venv
python3 -m venv WebScripts
cd WebScripts
source bin/activate
python3 -m pip install WebScripts
mkdir logs
```

### Windows
```bash
python -m venv WebScripts
cd WebScripts
Scripts\activate
python -m pip install WebScripts 
```

## Web Server (Using Debian)

### NGINX - As a proxy HTTPS

#### WebScripts Service

```bash
useradd --system --no-create-home --shell /bin/false WebScripts
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
chown -R WebScripts /path/to/virtualenv/
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

#### Install and WSGI main file

```bash
sudo apt install libexpat1
sudo apt install apache2 apache2-utils ssl-cert libapache2-mod-wsgi-py3

sudo mkdir /var/www/WebScripts
sudo chown -R www-data:www-data /var/www/WebScripts
sudo nano /var/www/WebScripts/wsgi.py
```

```python
#!/path/to/virtualenv/bin/python3

activator = '/path/to/virtualenv/bin/activate_this.py'
with open(activator) as f:
    exec(f.read(), {'__file__': activator})

from WebScripts.WebScripts import (
    server_path, 
    Configuration, 
    get_server_config, 
    add_configuration,
    logs_configuration,
    Server,
)
from typing import List
from os import path
import logging

class Paths:

    """This class define configuration files."""

    def __init__(self, config_cfg: List[str], config_json: List[str]):
        self.config_cfg = config_cfg
        self.config_json = config_json

logging.config.fileConfig(
    path.join(server_path, "config", "loggers.ini"),
    disable_existing_loggers=False,
)
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)",
    datefmt="%d/%m/%Y %H:%M:%S",
    encoding="utf-8",
    level=0,
    filename="/path/to/logs/root.logs",
    force=True,
)

paths = Paths([], [])

configuration = Configuration()
for config in get_server_config(paths):
    configuration = add_configuration(configuration, config)

logs_configuration(configuration)

configuration.set_defaults()
configuration.check_required()
configuration.get_unexpecteds()
configuration.build_types()

server = Server(configuration)

application = server.app
```

```bash
nano /path/to/virtualenv/bin/activate_this.py
```

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
        "You must run this like execfile('path/to/active_this.py', dict(__file__='path/to/activate_this.py'))")
import sys
import os

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
site_packages = os.path.join(base, 'lib', 'python%s' % sys.version[:3], 'site-packages')
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

#### Configure Apache

```bash
sudo chown www-data:www-data /path/to/virtualenv/bin/activate_this.py

sudo mkdir /logs
sudo touch /logs/apache-errors.logs
sudo touch /logs/apache-custom.logs
sudo touch /logs/root.logs
sudo chown -R www-data:www-data /logs

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

    WSGIScriptAlias / /var/www/WebScripts/wsgi.py
    WSGIDaemonProcess webscripts.com processes=1 threads=15 display-name=%{GROUP}
    WSGIProcessGroup webscripts.com

    DocumentRoot /var/www/WebScripts
    DirectoryIndex index.html

    Alias /robots.txt /var/www/WebScripts/robots.txt
    Alias /favicon.ico /var/www/WebScripts/favicon.ico

    LogLevel info
    ErrorLog /logs/apache-errors.logs
    CustomLog /logs/apache-custom.logs combined

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
