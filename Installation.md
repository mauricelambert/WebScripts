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

## Logs directory

Create a directory named `logs` to launch the *WebScripts Server*.

```bash
mkdir logs
```

## Linux Configurations

On Linux the default configurations **may not work**, replace all *script launchers* with `python3` (default is `python`).

## Start the server

You can now start the server with this simple command:
```bash
WebScripts
```

## First connection

To log in for the first time, use the `Admin` account (username: `Admin`, password: `Admin`). I recommend changing the password **immediately**. The `Admin` account is restricted on `192.168.*`, `172.16.*`,`10.*` and `127.0.*` (private network and localhost) by default.

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
