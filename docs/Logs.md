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
 4. Value: `20`, is `INFO`
 5. Value: `10`, is `DEBUG`
 6. Value: `5`, is `TRACE`

### Loggers

 - `console`: *print* logs with level greater than `DEBUG(10)` in stdout
 - `file`: write logs with level greater than `DEBUG(10)` in `logs/00-server.logs`
 - `log_trace`: write logs `TRACE` in `logs/05-trace.logs`
 - `log_debug`: write logs `DEBUG` in `logs/10-debug.logs`
 - `log_info`: write logs `INFO` in `logs/20-info.logs`
 - `log_warning`: write logs `WARNING` in `logs/30-warning.logs`
 - `log_error`: write logs `ERROR` in `logs/40-error.logs`
 - `log_critical`: write logs `CRITICAL` in `logs/50-critical.logs`

### Exceptions

If an *exceptions* is catched by the *WebScripts Server*, it will be written in `console`, `file` and `log_error` loggers.

### Console

In `console` logger i added *terminal colors* to quickly identify logs level:

 - `DEBUG` logs are *green*
 - `INFO` logs are *blue*
 - `WARNING` logs are *yellow*
 - `ERROR` logs are *purple*
 - `CRITICAL` logs are *red*

### File Rotation and compression

Log files rotate when the logs exceed 10MB and are compressed.

## Linux

On linux *WebScripts* logs with level `DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL` are redirected in **syslog**.

## Windows

On Windows if `pywin32` is installed logs with level `DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL` are redirected in **EventViewer**.
