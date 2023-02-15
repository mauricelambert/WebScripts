# Logs

## Logs directory

Create a directory named `logs` to launch the *WebScripts Server*. If `logs` directory does not exists or is not a directory, the WebScripts Server will try to create it.

```bash
mkdir logs
```

## Default logging

### Level

The logs level is "0" (all logs are written).
You can change the logging level in configuration files or by using command line arguments.

**Recommended**: In production (for security reasons) the log level should be `0` or `DEBUG`.

The *WebScripts Server* use six differents levels:

 1. Value: `50`, is `CRITICAL`
 2. Value: `40`, is `ERROR`
 3. Value: `30`, is `WARNING`
 3. Value: `27`, is `COMMAND`
 3. Value: `26`, is `RESPONSE`
 3. Value: `25`, is `ACCESS`
 4. Value: `20`, is `INFO`
 5. Value: `10`, is `DEBUG`
 6. Value: `5`, is `TRACE`

### Loggers

 - `console`: *print* logs with level greater than `DEBUG(10)` in stdout
 - `file`: write logs with level greater than `DEBUG(10)` in `logs/00-server.logs`
 - `log_trace`: write logs `TRACE` in `logs/05-trace.logs`
 - `log_debug`: write logs `DEBUG` in `logs/10-debug.logs`
 - `log_info`: write logs `INFO` in `logs/20-info.logs`
 - `logger_access`: write logs `ACCESS` in `logs/25-access.logs`
 - `logger_response`: write logs `RESPONSE` in `logs/26-response.logs`
 - `logger_command`: write logs `COMMAND` in `logs/27-command.logs`
 - `log_warning`: write logs `WARNING` in `logs/30-warning.logs`
 - `log_error`: write logs `ERROR` in `logs/40-error.logs`
 - `log_critical`: write logs `CRITICAL` in `logs/50-critical.logs`

### Exceptions

If an *exceptions* is catched by the *WebScripts Server*, it will be written in `console`, `file` and `log_error` loggers.

### Console

In `console` logger i added *terminal colors* to quickly identify logs level:

 - `DEBUG` logs are *green*
 - `INFO` logs are *blue*
 - `ACCESS` logs are *cyan*
 - `RESPONSE` logs are *cyan*
 - `COMMAND` logs are *cyan*
 - `WARNING` logs are *yellow*
 - `ERROR` logs are *purple*
 - `CRITICAL` logs are *red*

### File Rotation and compression

Log files rotate when the logs exceed 10MB and logs archive are compressed.

## Linux

On linux *WebScripts* logs with level `DEBUG`, `INFO`, `ACCESS`, `RESPONSE`, `COMMAND`, `WARNING`, `ERROR` and `CRITICAL` are redirected in **syslog**.

## Windows

On Windows if `pywin32` is installed logs with level `DEBUG`, `INFO`, `ACCESS`, `RESPONSE`, `COMMAND`, `WARNING`, `ERROR` and `CRITICAL` are redirected in **Windows Events**.

## Write logs in your own scripts

To group the logs you can use the following environment variable: `LOG_PATH`. This is the path of the WebScripts logs. I recommend using the following path for your script: `LOG_PATH/<script category>/<script name>.log`.

You can use the [WebScriptsTools](https://github.com/mauricelambert/WebScriptsTools) package to get the log file. It's possible to get it using command line or import it in python script. Read the [README.md](https://github.com/mauricelambert/WebScriptsTools#readme), you have some examples on this repository.

**Caution:** To protect your WebScripts server and your system is recommended to change the working directory permissions and owner (`root:root 755`), your script can not create a file in script directory and working directory. **You can not make a log file in the working directory or script directory.**

## Configuration

The configuration can be edited, you can write your own configuration file, in `./config/logger.ini`, based on the WebScripts *logger.ini*. The WebScripts server use the default *python logging* library, get the documentation [here](https://docs.python.org/).
