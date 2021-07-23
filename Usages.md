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

### Mode debug

 - To get python error message and traceback on page 500.
 - To get the existing URLs on page 404.
 - To export the server configuration to the JSON file named export_Configuration.json.
```bash
WebScripts --debug
WebScripts -d
```

### Mode not secure

 - Do not use HTTP security headers, useful for debugging web scripts (*javascript*)
```bash
WebScripts --security
WebScripts -s
```

### Accept unauthenticated user

```bash
WebScripts --accept-unauthenticated-user --accept-unknow-user
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

### Desactive authentication script

```bash
WebScripts --active-auth
WebScripts -a
```

### Auth script

```bash
WebScripts --auth-script "auth.py"
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
WebScripts --documentations-path "./doc/1/" "./doc/2/" --documentations-path "./doc/3/"
WebScripts -D "./doc/1/" "./doc/2/" -D "./doc/3/"
```

### Javascript paths

```bash
WebScripts --js-path "./js/1/" "./js/2/" --js-path "./js/3/"
WebScripts -J "./js/1/" "./js/2/" -J "./js/3/"
```

### Static paths

```bash
WebScripts --statics-path "./images/1/" "./templates/html/2/" --statics-path "./css/3/"
WebScripts -T "./images/1/" "./templates/html/2/" -T "./css/3/"
```

### Log level

 - Configure the *root* logger (other loggers are not impacted)
 - Level must be in {0 DEBUG INFO WARNING ERROR CRITICAL}
```bash
WebScripts --log-level DEBUG
WebScripts -l DEBUG
```

### Log filename

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-filename "logs.log"
WebScripts -f "logs.log"
```

### Log encoding

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-encoding "utf-8"
```

### Log format

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-format "%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)"
```

### Log date format

 - Configure the *root* logger (other loggers are not impacted)
```bash
WebScripts --log-date-format "%d/%m/%Y %H:%M:%S"
```

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
