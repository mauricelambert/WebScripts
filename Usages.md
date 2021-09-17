# Usages

## Commands line

```bash
WebScripts
```

Using the python module:

### Linux
```bash
python3 -m WebScripts
```

### Windows
```bash
python -m WebScripts
```

## Arguments

### Help message
```bash
WebScripts --help
WebScripts -h
```

### Change interface and port
```bash
WebScripts --interface "192.168.1.2" --port 80
WebScripts -i "192.168.1.2" -p 80
```

### Add configuration from INI files

```bash
WebScripts --config-cfg "config1.ini" "config2.ini" --config-cfg "config3.ini"
WebScripts -c "config1.ini" "config2.ini" -c "config3.ini"
```

### Add configuration from JSON files

```bash
WebScripts --config-json "config1.json" "config2.json" --config-json "config3.json"
WebScripts -j "config1.json" "config2.json" -j "config3.json"
```

### Script paths

```bash
WebScripts --scripts-path "./scripts/1/" "./scripts/2/" --scripts-path "./scripts/3/"
WebScripts -S "./scripts/1/" "./scripts/2/" -S "./scripts/3/"
```

### Script configuration paths

```bash
WebScripts --scripts-config "./config/1/*.json" "./config/2/*.ini" --scripts-config "./config/3/*.json"
WebScripts -S "./config/1/*.json" "./config/2/*.ini" -S "./config/3/*.json"
```

### Modules

```bash
WebScripts --modules "module1" "module2" --modules "module3"
WebScripts -m "module1" "module2" -m "module3"
```

### Module paths

```bash
WebScripts --modules-path "./modules/1/" "./modules/2/" --modules-path "./modules/3/"
WebScripts -I "./modules/1/" "./modules/2/" -I "./modules/3/"
```

### Documentation paths

```bash
WebScripts --documentations-path "./doc/1/*.html" "./doc/2/*.txt" --documentations-path "./doc/3/*.html"
WebScripts -D "./doc/1/*.html" "./doc/2/*.txt" -D "./doc/3/*.html"
```

### Javascript paths

```bash
WebScripts --js-path "./js/1/*.js" "./js/2/*.js" --js-path "./js/3/*.js"
WebScripts -J "./js/1/*.js" "./js/2/*.js" -J "./js/3/*.js"
```

### Static paths

```bash
WebScripts --statics-path "./images/1/*.jpg" "./templates/html/2/*.html" --statics-path "./css/3/*.css"
WebScripts -T "./images/1/*.png" "./templates/html/2/*.html" -T "./pdf/3/*.pdf"
```

### AUTH

### Desactive authentication script

```bash
WebScripts --active-auth
WebScripts -a
```

### Auth script

```bash
WebScripts --auth-script "auth.py"
```

### Accept unauthenticated user

```bash
WebScripts --accept-unauthenticated-user --accept-unknow-user
```

### Auth failures to blacklist

```bash
WebScripts --auth-failures-to-blacklist 3
WebScripts -b 3
```

### Blacklist time

```bash
WebScripts --blacklist-time 30
WebScripts -B 30
```

### Paths without authentication

```bash
WebScripts --exclude-auth-paths "/auth/" "/help/" --exclude-auth-paths "/contacts/"
WebScripts --e-auth-paths "/auth/" "/help/" --e-auth-paths "/contacts/"
```

### Pages without authentication

```bash
WebScripts --exclude-auth-pages "/auth/page.py" "/help/page.html" --exclude-auth-pages "/contacts/page.html"
WebScripts --e-auth-pages "/auth/page.py" "/help/page.html" --e-auth-pages "/contacts/page.html"
```

### DEV

#### Mode debug

 - To get python error message and traceback on page 500.
 - To get the existing URLs on page 404.
 - To export the server configuration to the JSON file named export_Configuration.json.
```bash
WebScripts --debug
WebScripts -d
```

#### Mode not secure

 - Do not use HTTP security headers, useful for debugging web scripts (*javascript*)
 - Active the Content-Security-Policy-Report-Only header
 - Active the debug module for Content-Security-Policy (URL: "/csp/debug/")
```bash
WebScripts --security
WebScripts -s
```

### LOGS

#### Level

 - Configure the *root* logger (other loggers are not impacted)
 - Level must be in {0 DEBUG INFO WARNING ERROR CRITICAL}
```bash
WebScripts --log-level DEBUG
WebScripts -l DEBUG
```

#### Filename

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-filename "logs.log"
WebScripts -f "logs.log"
```

#### Encoding

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-encoding "utf-8"
```

#### Format

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-format "%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)"
```

#### Date format

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-date-format "%d/%m/%Y %H:%M:%S"
```

### SMTP

#### Server

 - Configure the SMTP server name to send email notifications
```bash
WebScripts --smtp-server "my.smtp.server"
WebScripts --s-server "my.smtp.server"
```

#### StartTLS

 - Configure the secure connection with StartTLS
```bash
WebScripts --smtp-starttls
WebScripts --s-tls
```

#### Password

 - Configure the SMTP login (username is the `notification_address` configuration), if password is None the WebScripts Server send the email notifications without authentication.
```bash
WebScripts --smtp-password "password"
WebScripts --s-password "password"
```

#### Port

 - Configure the SMTP server port
```bash
WebScripts --smtp-port 25
WebScripts --s-port 25
```

#### SSL

 - Configure the secure connection with SSL
```bash
WebScripts --smtp-ssl
WebScripts --s-ssl
```

#### Receivers/Administrators email addresses

 - Configure the receivers email addresses (should be the administrators addresses)
```bash
WebScripts --admin-adresses "admin1@my.smtp.server" "admin2@my.smtp.server" --admin-adresses "admin3@my.smtp.server"
WebScripts --a-adr "admin1@my.smtp.server" "admin2@my.smtp.server" --a-adr "admin3@my.smtp.server"
```

#### Sender

 - Configure the sender email address
```bash
WebScripts --notification-address "notification@my.smtp.server"
WebScripts --n-adr "notification@my.smtp.server"
```

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
