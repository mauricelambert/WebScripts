# Development and Administration Tools

## Notifications

To configure the email notification read the [documentation for email notification](https://github.com/mauricelambert/WebScripts/wiki/Server-Configuration#server-configuration).

For temp configuration or tests i recommend to use [command line arguments](https://github.com/mauricelambert/WebScripts/wiki/Usages#smtp).

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
| WebScripts.py | 498        | 4       | 99%      |
| utils.py      | 297        | 7       | 98%      |
| Errors.py     | 27         | 0       | 100%     |


### Hardening audit

Hardening test is coming.

### Functional tests and WebScripts pentest tool

Functional tests and WebScripts pentest tool.
