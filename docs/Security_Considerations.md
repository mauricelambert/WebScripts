# Security Considerations

An example of deployment for production is available [here](https://webscripts.readthedocs.io/en/latest/Deployment/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Deployment)) using NGINX and python virtual environment. This example respect all security considerations defined in this page.

## Installations

### Secure server and connection

 - I recommend using a **HTTPS proxy** on production environments (to protect against `MiM` attacks and protect the *WebScripts Server*).

### Virtual environments

 - I recommend using a python virtual environment

## Configurations

### Interface

 - The *WebScripts Server* **is not secure enough** to be used directly on public interface (the proxy is very important). It **should not** use an interface other than `127.0.0.1`. 

### HTTP headers

 - To protect your WEB clients (against `XSS`, `CSRF`, `MiM` and other threats) the configuration named `security` of the *WebScripts Server* sends HTTP headers. This configuration should be `true`. The headers are:
    - `Strict-Transport-Security`: `max-age=63072000; includeSubDomains; preload`
    - `Content-Security-Policy`: `default-src 'self'; form-action 'none'`
    - `X-Frame-Options`: `deny`
    - `X-XSS-Protection`: `1; mode=block`
    - `X-Content-Type-Options`: `nosniff`
    - `Referrer-Policy`: `origin-when-cross-origin`
    - `Cache-Control`: `no-store`
    - `Clear-Site-Data`: `*`
    - `Feature-Policy`: `payment 'none'; geolocation 'none'; microphone 'none'; camera 'none'`
    - `Permissions-Policy`: `microphone=(),camera=(),payment=(),geolocation=()`
    - `Cross-Origin-Embedder-Policy`: `require-corp`
    - `Cross-Origin-Opener-Policy`: `same-origin`
    - `Cross-Origin-Resource-Policy`: `same-origin`

### Debugging

 - The `debug` configuration should be `false`, if set to `true` some code and configuration information will no longer be protected.

### Bruteforce

 - `auth_failures_to_blacklist` and `blacklist_time` configuration should be set, to protect your passwords againts bruteforce attacks.

### SMTP password

 - In the production environment, you must be notified from your WebScripts server, configure SMTP (server, email addresses...) to receive notifications.
 - Do not use SMTP password (`smtp_password != None`) without StartTLS (`smtp_starttls == True`) or SSL (`smtp_ssl == True`). If connection is not secure the password may be sniffed.

### Script configurations

#### Logs

 - You should set to `true` the `no_password` configuration when you don't have a password in command lines arguments to logs command line.

#### Content type

 - You should never set `stderr_content_type` to `text/html` because it may be used for XSS (HTML and javascript injection).
 - Some script required the `text/html` as `content_type`, i should use [specific function for XSS protection](#XSS).
 - Don't unescape HTML special characters in *console* scripts (when `content_type` is `text/plain`), the javascript does it for you.

### Timeout

 - You should set the `timeout` configuration.

## Credentials

Change the password of the `Admin` user and the API key or use custom authentication script, database and system.

## System

### Files rigths and access

Some files and directories must be protected by the system, to avoid **privilege escalation**, **RCE** (*Remote Code Execution*) or other attacks. 

#### READ-ONLY: scripts, executables and configurations

1. Scripts, executables and configurations should **never** have *setuid*, *setgid*, *sticky bit* or other special permissions.
2. Scripts, executables and configurations should **never** have the write permissions and any permissions for *group* and *other*
    - Use this command to protect your executables: `chmod 100 <file>`
    - Use this command to protect your scripts and configurations: `chmod 400 <file>`
3. The directories of scripts, executables and configurations should **always have** *root* as *owner* and **never** *write permissions* for *group* and *other*
    1. Use this command to change the *owner* as root: `chown root:root <directory>`
    2. Use this command to change *permissions*: `chmod 755 <directory>`

#### READ and WRITE: data and logs

To protect your files the read and write files, you need to change permissions on *group* and *other* (on Linux run this command: `chmod -R 600 <directory or file>`) and make sure the owner is the user who is launching the *WebScript Server* (on Linux run this command: `chown -R <user>:<user> <directory or file>`).

The files and directories that need protection:

 - `<lib path>/data/`: encrypted or hashed passwords are stored here, user permissions are also set here
 - `./logs/`: logs contains informations about configurations

### Delete files

 - `./export_Configuration.json` is useful for debugging but it should be removed on production environments.

### System administration

The WebScripts is a tool that can help you administer other system (using *SSH* or *WinRM* scripts for example) but **never** the WebScripts Server system. If your scripts can change the *system* configurations, an attacker can also use it. The principle is as follow: the system protects your WebScripts server and the WebScripts server must not change the system.

## Remote Code Excution

You **should never use** a function to execute string as code on *users inputs*.
A remote code execution is **very dangerous**.

 - I show some examples here but these are not exhaustive.
 - You can use other languages, read the documentation and pay attention to the functions `exec`, `shell`, `eval`, ....

### Python

Some examples of **Remote Code Execution** on *WebScripts custom module*:
```python
def page(environ, user, configuration, filename, arguments, inputs, *args, csrf_token=None):

    """Some examples of remote code executions are shown in this function, 
    you should never use this example or an equivalent."""
    
    eval(environ["HTTP_COMMAND"]) # Run the Command HTTP headers as python code
    exec(filename)                # Run the URL parameter as python code
    os.system(arguments[0])       # Run the first argument as a command line
    pickle.loads(inputs[0])       # De-serailize a pickle payload (Pickle contains weakness don't use it on user inputs)

    # Don't execute a (encrypted) cookie !

    return "200 OK", {}, "Response"
```

Some examples of **Remote Code Execution** on python script:
```python
import pickle
import sys

eval(environ["HTTP_COMMAND"])        # Run the Command HTTP headers as python code
eval(sys.argv[1])                    # Run the first argument as python code
eval(input())                        # Run stdin as python code

exec(environ["HTTP_COMMAND"])        # Run the Command HTTP headers as python code
exec(sys.argv[1])                    # Run the first argument as python code
exec(input())                        # Run stdin as python code

os.system(environ["HTTP_COMMAND"])   # Run the Command HTTP headers as a command line
os.system(sys.argv[1])               # Run the first argument as a command line
os.system(input())                   # Run stdin as a command line

pickle.loads(environ["HTTP_COMMAND"])# De-serailize the Command HTTP headers as a pickle payload (Pickle contains weakness don't use it on user inputs)
pickle.loads(sys.argv[1])            # De-serailize the Command HTTP headers as a pickle payload (Pickle contains weakness don't use it on user inputs)
pickle.loads(input())                # De-serailize the Command HTTP headers as a pickle payload (Pickle contains weakness don't use it on user inputs)
```

### Bash

Some examples of **Remote Code Execution** in bash script:
```bash
eval $1                           # Run the first argument as a command line
$1                                # Run the first argument as a command line

python3 -c "${1}"                 # Run the first argument as python code
php -r "${1}"                     # Run the first argument as php code
```

### PHP

Some examples of **Remote Code Execution** in php script:
```php
<?php 
  shell_exec($argv[1]);           // Run the first argument as a command line
  eval($argv[1]);                 // Run the first argument as php code
?>
```

## XSS

You should never print a user entry (headers, arguments, inputs, URLs, content, username, cookie, ...), when the output `content-type` is set to `text/html`,  without change HTML scpecial characters.

### Python

```python
import html

print(html.escape(user.name))
```

### PHP

```php
<?php
    echo(htmlspecialchars(cookie));
?>
```

## WebScripts Web Security

### Session

The *WebScripts Server* use `HTTP Cookies` for *session*.
The session are generated with `secrets.token_hex(64)`.
The cookie is set with this HTTP header: `Set-Cookie: SessionID=<user id>:<64 random byte hexadecimal>; Path=/; SameSite=Strict; Max-Age=3600; Secure; HttpOnly`.
Sessions can be used with only one IP address and expire after one hours.

### CSRF token

The server uses `CSRF tokens` for `POST` requests when a session is used.
The `CSRF tokens` are generated with `b64encode(secrets.token_bytes(48)).decode()`.
Tokens can only be used once, for one session and they expire after 300 seconds (5 minutes).

Cautions:

 - **BasicAuth** and **API keys** **should never** be used with a web browser because *CSRF protections* is not enabled with these methods.
