# Installation

[![Install WebScripts - Youtube](https://img.youtube.com/vi/KxyEGPW1IlY/0.jpg)](http://www.youtube.com/watch?v=KxyEGPW1IlY)

*Install WebScripts - Youtube video*

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

**Upgrade:**
```bash
python3 -m pip install --upgrade WebScripts
```

### Recommendations

#### Debian using Apache deployment

[Apache Deployment](https://webscripts.readthedocs.io/en/latest/Deployment/#apache-using-wsgi-mod) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment#apache-using-wsgi-mod))

```bash
python3 -m pip install WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=www-data"
# OR
python3 -m pip install WebScripts --install-option "-p<your password>" --install-option "-owww-data"
```

#### Debian using NGINX as HTTPS proxy 

[NGINX Deployment](https://webscripts.readthedocs.io/en/latest/Deployment/#nginx-as-a-proxy-https)) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment#nginx---as-a-proxy-https))

```bash
python3 -m pip install WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=WebScripts"
# OR
python3 -m pip install WebScripts --install-option "-p<your password>" --install-option "-oWebScripts"
```

## Windows

```bash
python -m pip install WebScripts
```

**Upgrade:**
```bash
python -m pip install --upgrade WebScripts
```

### Recommendations

```bash
python -m pip install WebScripts --install-option "--admin-password=<your password>"
# OR
python -m pip install WebScripts --install-option "-p<your password>"
```

### Optional

To centralize logs in Event Viewer.
```bash
python -m pip install pywin32
```

## Arguments

 - `--admin-password=` or `-p`: The administrator password (password of the default account named *Admin*)
 - `--owner=` or `-o`: Owner of installation files (used on UNIX systems only), to change the owner and permissions run the command with privileges
 - `--json-only` or `-j`: Delete INI configuration files (used with the `--no-hardening/-n` argument only)
 - `--no-hardening` or `-n`: Does not harden the installation of WebScripts **not recommended**

## Compatibility

### Python3.8

```bash
git clone https://github.com/mauricelambert/WebScripts.git   # Get the code
cd WebScripts                                                # Change the current directory
python3.8 WebScripts/scripts/to_3.8/to_3.8.py                # Execute the script for python3.8 compatibility
python3.8 setup38.py install -p "<your password>" -o "owner" # Install it
python3.8 -m WebScripts38                                    # Use WebScripts38
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

## Start the server

You can now start the server with this simple command:
```bash
WebScripts
```

## First connection

1. Install without `--admin-password=` option: to log in for the first time, use the `Admin` account (username: `Admin`, password: `Admin`). I recommend changing the password **immediately**. The `Admin` account is restricted on `127.0.*,192.168.*,172.16.*,10.*` by default.
2. Install with `--admin-password=` option: to log in for the first time, use the `Admin` account (username: `Admin`).

## Logs directory

Create a directory named `logs` to launch the *WebScripts Server*. If `logs` directory does not exists or is not a directory, the WebScripts Server will try to create it.

```bash
mkdir logs
```

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
