# Deployment

## Python virtual environment

### Linux
```bash
python3 -m pip install --upgrade venv
python3 -m venv WebScripts
cd WebScripts
source bin/activate
python3 -m pip install WebScripts
```

### Windows
```bash
python -m pip install --upgrade venv
python -m venv WebScripts
cd WebScripts
Scripts\activate
python -m pip install WebScripts 
```

## NGINX

### Linux (Debian)

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
    root /home/kali/Documents/WebScripts/WebScripts;
    ssl_certificate     /home/kali/Documents/certificat/nginx.crt;
    ssl_certificate_key /home/kali/Documents/certificat/nginx.key;
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
