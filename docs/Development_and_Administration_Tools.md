# Development and Administration Tools

## Notifications

To configure the email notification read the [documentation for email notification](https://webscripts.readthedocs.io/en/latest/Server_Configuration/#server-configuration) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Server-Configuration#server-configuration)).

For temp configuration or tests i recommend to use [command line arguments](https://webscripts.readthedocs.io/en/latest/Usages/#smtp) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/Usages#smtp)).

## Debug the Content Security Policy

To debug the CSP you may use the `--security` arguments (i should not change the `security` configuration for security reason) and configure the email notification. You have a `application/json` page on `http(s)://<server>:<port>/csp/debug/` with the `Content Security Policy Report`

```bash
WebScripts --security --admin-adresses "admin@email.com" --n-adr "notification@email.com" --s-server "smtp.email.com"
```

## Tests

### Unittest

```bash
python -m unittest discover -s test -p Test*.py -v
```

| File          | Statements | missing | coverage |
|---------------|------------|---------|----------|
| WebScripts.py | 514        | 4       | 99%      |
| commons.py    | 378        | 1       | 99%      |
| utils.py      | 308        | 6       | 98%      |
| Errors.py     | 27         | 0       | 100%     |


### Hardening audit

1. To harden the WebScripts installation: run the installation command with privileges using these arguments: `--admin-password=\-p` and `--owner=\-o`. See the examples on [installation page](https://webscripts.readthedocs.io/en/latest/Installation/) and [deployment page](https://webscripts.readthedocs.io/en/latest/Deployment/).
2. The hardening audit is performed when WebScripts server starts. The audit report is written in `audit.html`, `audit.json` and `audit.txt` and emailed to Administrators.
HTML report examples:
    - [Windows](https://mauricelambert.github.io/info/python/code/WebScripts/audit_windows.html)
    - [Linux](https://mauricelambert.github.io/info/python/code/WebScripts/audit_linux.html)

### Functional tests and WebScripts pentest tool

Functional tests and WebScripts pentest tool.
