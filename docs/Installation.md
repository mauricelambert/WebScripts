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
python3 -m venv WebScripts        # Make a virtual environment for WebScripts
source WebScripts/bin/activate    # Activate your virtual environment
sudo WebScripts/bin/python3 -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=<owner>" --install-option "--directory=./WebScripts"     # Install WebScripts using setup.py with pip
sudo WebScripts/bin/python3 -m WebScripts.harden -p '<my admin password>' -o '<my webscripts user>' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

### Recommendations

#### Debian using Apache deployment

[Apache Deployment](https://webscripts.readthedocs.io/en/latest/Deployment/#apache-using-wsgi-mod) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment#apache-using-wsgi-mod))

```bash
python3 -m venv WebScripts        # Make a virtual environment for WebScripts
source WebScripts/bin/activate    # Activate your virtual environment
sudo WebScripts/bin/python3 -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=www-data" --install-option "--directory=./WebScripts"     # Install WebScripts using setup.py with pip
sudo WebScripts/bin/python3 -m WebScripts.harden -p '<my admin password>' -o 'www-data' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

#### Debian using NGINX as HTTPS proxy 

[NGINX Deployment](https://webscripts.readthedocs.io/en/latest/Deployment/#nginx-as-a-proxy-https)) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment#nginx---as-a-proxy-https))

```bash
python3 -m venv WebScripts        # Make a virtual environment for WebScripts
source WebScripts/bin/activate    # Activate your virtual environment
sudo WebScripts/bin/python3 -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--owner=WebScripts" --install-option "--directory=./WebScripts"     # Install WebScripts using setup.py with pip
sudo WebScripts/bin/python3 -m WebScripts.harden -p '<my admin password>' -o 'WebScripts' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

## Windows

```bash
python -m venv WebScripts        # Make a virtual environment for WebScripts
WebScripts/Scripts/activate    # Activate your virtual environment
WebScripts/Scripts/python -m pip install --use-pep517 WebScripts --install-option "--admin-password=<your password>" --install-option "--directory=.\WebScripts"     # Install WebScripts using setup.py with pip
WebScripts/Scripts/python -m WebScripts.harden -p '<my admin password>' -o '' -d 'WebScripts/'  # Harden default configurations
cd WebScripts                     # Use your virtual environment to start WebScripts
WebScripts                        # Start WebScripts server for demonstration (for production see deployment documentation)
```

### Optional

To centralize logs in Event Viewer.

```bash
python -m pip install pywin32
```

## Arguments

 - `--admin-password=` or `-p`: The administrator password (password of the default account named *Admin*)
 - `--owner=` or `-o`: Owner of installation files (used on UNIX systems only), to change the owner and permissions run the command with privileges
 - `--directory` or `-d`: Location where WebScripts will be launched, to have secure owner and permissions and to add hardening files

## Upgrade

### Since version 3.0.0

Your data directory is moved into your working directory by the *hardening script*. You don't need to move it to keep data when you upgrade python. Is not recommended to change the library configuration/static files (you can override it with your own configuration files in the wworking directory), so you don't need to backup it and restore it.

Run: `python3 -m pip install --upgrade WebScripts`

### Before WebScripts3

1. Backup data files: `<WebScripts env>/lib/python3.*/site-packages/WebScripts/data`
2. This is not recommended, but if you have modified the library configuration files, back them up: `<WebScripts env>/lib/python3.9/site-packages/WebScripts/config/**/*.{json,ini}`
3. This is not recommended, but if you have modified the library static files, back them up: `<WebScripts env>/lib/python3.9/site-packages/WebScripts/static`
4. Upgrade WebScripts: `python3 -m pip install --upgrade WebScripts`
5. Restore files
6. Restart the server

```bash
#!/usr/bin/env bash

# Little bash script to upgrade your WebScripts Server.
# Assume you run this script in the environment directory.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: you must be root to launch this script"
    exit 1
fi

echo "Active WebScripts environment..."
dir1=$(pwd)
source ./bin/activate
cd lib/python3.*/site-packages/WebScripts
dir2=$(pwd)

echo "Move data files..."
mkdir -p /tmp/WebScripts/
mv -f data /tmp/WebScripts/

# Uncomment following lines to backup configuration files
# echo "Move configuration files..."
# mv -f config /tmp/WebScripts/

# Uncomment following lines to backup static files
# echo "Move static files..."
# mv -f static /tmp/WebScripts/

cd ..
python3 -m pip install --upgrade --force-reinstall WebScripts
cd "${dir2}"

echo "Restore data files..."
rm -rf data
mv -f /tmp/WebScripts/data ./

# Uncomment following lines to restore configuration files
# echo "Move configuration files..."
# [[ -e config.bak ]] && rm -rf config.bak
# [[ -e config ]] && mv config config.bak
# mv -f /tmp/WebScripts/config ./

# Uncomment following lines to restore static files
# echo "Move static files..."
# [[ -e static.bak ]] && rm -rf static.bak
# [[ -e static ]] && mv static static.bak
# mv -f /tmp/WebScripts/static ./

# systemctl restart httpd  # restart server Apache/WSGI/WebScripts on RedHat
# systemctl restart apache # restart server Apache/WSGI/WebScripts on Debian

echo "Upgrade is done ! Please restart your WebScripts server."
exit 0
```

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

1. Install without `--admin-password=` option: to log in for the first time, use the `Admin` account (username: `Admin`, password: `Admin`). I recommend changing the password **immediately**. The `Admin` account is restricted on `127.0.*,192.168.*,172.16.*,10.*` IP addresses by default.
2. Install with `--admin-password=` option: to log in for the first time, use the `Admin` account (username: `Admin`).

## Logs directory

Create a directory named `logs` to launch the *WebScripts Server*. If `logs` directory does not exists or is not a directory, the WebScripts Server will try to create it.

```bash
mkdir logs
```

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
