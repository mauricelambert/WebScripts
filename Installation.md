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

**Upgrade:**
```bash
python3 -m pip install --upgrade WebScripts
```

## Windows

```bash
python -m pip install WebScripts
```

**Upgrade:**
```bash
python -m pip install --upgrade WebScripts
```

### Optional

To centralize logs in Event Viewer.
```bash
python -m pip install pywin32
```

## Compatibility

### Python3.8

```bash
git clone https://github.com/mauricelambert/WebScripts.git  # Get the code
cd WebScripts                                               # Change the current directory
python3.8 WebScripts/scripts/to_3.8/to_3.8.py               # Execute the script for python3.8 compatibility
python3.8 setup38.py install                                # Install it
python3.8 -m WebScripts38                                   # Use WebScripts38
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

To log in for the first time, use the `Admin` account (username: `Admin`, password: `Admin`). I recommend changing the password **immediately**. The `Admin` account is restricted on `192.168.*`, `172.16.*`,`10.*` and `127.0.*` (private network and localhost) by default.

## Logs directory

Create a directory named `logs` to launch the *WebScripts Server*. If `logs` directory does not exists or is not a directory, the WebScripts Server will try to create it.

```bash
mkdir logs
```

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
