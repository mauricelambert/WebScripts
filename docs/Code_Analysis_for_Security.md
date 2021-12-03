# Code Analysis for Security

## SAST alerts

1. A vulnerability is found with: `Popen(..., shell=True, ...)` used for generating documentation. The vulnerability is not dangerous if the configrations files are protected by the system (rights and write permissions to these files).

## DAST alerts

### ZAP

1. Correct by deployment:
    - **HTTP Only Site** (*configure HTTPS with Apache or NGINX*)
    - **Web Cache Deception** (*secure by Apache or NGINX*)
    - **Server Leaks Version Information via "Server" HTTP Response Header Field** (*Server header is set by Apache or NGINX*)
2. False positive:
    - **Application Error Disclosure** (*error message for error 500 on script execution*)
    - **Base64 Disclosure** (*CSRF token*)
    - **Information Disclosure - Suspicious Comments** (*copyright*)
3. No correction:
    - **User Agent Fuzzer** (*this WebServer is for computer only, not for mobile or other device*)
    - **Modern Web Application** (*pydoc documentation pages*)
    - **Deprecated Feature Policy Header Set** (*Feature-Policy is set for older web browsers*)
    - **Non-Storable Content**

### Skipfish

1. Correct by deployment:
    - **New 'Server' header value seen** (*Server header is set by Apache or NGINX*)
2. False positive:
    - **Hidden files / directories** (*the /auth/ page*)
    - **Resource not directly accessible** (*are not resources*)
    - **New 404 signature seen** (*first is a redirection, second is 404*)
    - **New 'X-\*' header value seen** (*Security headers*)
3. No correction:
    - **Node should be a directory, detection error?** (*WebScripts implementation*)
    - **Server error triggered** (*WebScripts implementation*)
    - **New 'X-\*' header value seen** (*Server header*)

## Reports

Github Actions and Gitlab-CI scan and generate these reports.

 - [bandit.txt](https://mauricelambert.github.io/info/python/code/WebScripts/bandit.txt)
 - [dirb.txt](https://mauricelambert.github.io/info/python/code/WebScripts/dirb.txt)
 - [nikto.html](https://mauricelambert.github.io/info/python/code/WebScripts/nikto.html)
 - [ZAP.html](https://mauricelambert.github.io/info/python/code/WebScripts/ZAP.html)
 - [skipfish](https://mauricelambert.github.io/info/python/code/WebScripts/skipfish/index.html)
 - [whatweb](https://mauricelambert.github.io/info/python/code/WebScripts/whatweb.json)

### Bandit

```bash
bandit -i -l -r -v -f json -o "vulns.json" --ignore-nosec WebScripts
```

```json
{
  "errors": [],
  "generated_at": "2021-12-02T18:36:59Z",
  "metrics": {
    "WebScripts\\Errors.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 52,
      "nosec": 0
    },
    "WebScripts\\Pages.py": {
      "CONFIDENCE.HIGH": 3.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 1.0,
      "SEVERITY.LOW": 2.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 773,
      "nosec": 0
    },
    "WebScripts\\WebScripts.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 1076,
      "nosec": 0
    },
    "WebScripts\\__init__.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 25,
      "nosec": 0
    },
    "WebScripts\\__main__.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 25,
      "nosec": 0
    },
    "WebScripts\\commons.py": {
      "CONFIDENCE.HIGH": 3.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 3.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 819,
      "nosec": 0
    },
    "WebScripts\\hardening.py": {
      "CONFIDENCE.HIGH": 1.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 1.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 1228,
      "nosec": 0
    },
    "WebScripts\\modules\\csp.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 53,
      "nosec": 0
    },
    "WebScripts\\modules\\error_pages.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 574,
      "nosec": 0
    },
    "WebScripts\\modules\\share.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 176,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\add_group.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 41,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\add_user.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 91,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\api_view_groups.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 64,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\api_view_users.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 62,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\auth.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 81,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\change_my_password.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 62,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\change_user_password.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 48,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\delete_group.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 40,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\delete_user.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 39,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\get_apikey.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 39,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\modules\\manage_defaults_databases.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 339,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\view_groups.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 70,
      "nosec": 0
    },
    "WebScripts\\scripts\\account\\view_users.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 75,
      "nosec": 0
    },
    "WebScripts\\scripts\\doc\\py_doc.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 57,
      "nosec": 0
    },
    "WebScripts\\scripts\\logs\\log_analysis.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 82,
      "nosec": 0
    },
    "WebScripts\\scripts\\logs\\log_viewer.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 70,
      "nosec": 0
    },
    "WebScripts\\scripts\\passwords\\get_password_share.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 1.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 1.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 129,
      "nosec": 0
    },
    "WebScripts\\scripts\\passwords\\new_password_share.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 130,
      "nosec": 0
    },
    "WebScripts\\scripts\\passwords\\password_generator.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 29,
      "nosec": 0
    },
    "WebScripts\\scripts\\py\\hello.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 28,
      "nosec": 0
    },
    "WebScripts\\scripts\\py\\show_license.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 55,
      "nosec": 0
    },
    "WebScripts\\scripts\\py\\test_config.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 20,
      "nosec": 0
    },
    "WebScripts\\scripts\\request\\delete_request.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 47,
      "nosec": 0
    },
    "WebScripts\\scripts\\request\\get_request.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 46,
      "nosec": 0
    },
    "WebScripts\\scripts\\request\\get_requests.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 60,
      "nosec": 0
    },
    "WebScripts\\scripts\\request\\modules\\requests_management.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 95,
      "nosec": 0
    },
    "WebScripts\\scripts\\to_3.8\\to_3.8.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 113,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\api_get_all_files.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 45,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\api_get_files.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 48,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\api_get_history.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 40,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\delete_file.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 38,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\get_all_files.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 61,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\get_any_file.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 56,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\get_file.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 57,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\get_files.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 56,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\get_history.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 67,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\modules\\uploads_management.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 303,
      "nosec": 0
    },
    "WebScripts\\scripts\\uploads\\upload_file.py": {
      "CONFIDENCE.HIGH": 0.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 0.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 97,
      "nosec": 0
    },
    "WebScripts\\utils.py": {
      "CONFIDENCE.HIGH": 2.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 0.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 0.0,
      "SEVERITY.LOW": 2.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 530,
      "nosec": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 9.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 1.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 1.0,
      "SEVERITY.LOW": 8.0,
      "SEVERITY.MEDIUM": 1.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 8211,
      "nosec": 0
    }
  },
  "results": [
    {
      "code": "53 \n54 from subprocess import Popen, PIPE, TimeoutExpired  # nosec\n55 from typing import Tuple, List, Dict\n",
      "filename": "WebScripts\\Pages.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with Popen module.",
      "line_number": 54,
      "line_range": [
        54
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "158         stderr=PIPE,\n159         shell=False,\n160         env=script_env,\n161     )  # nosec\n162 \n163     stdout, stderr, key, error, code = start_process(\n164         script, process, user, inputs\n165     )\n166 \n",
      "filename": "WebScripts\\Pages.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 159,
      "line_range": [
        154,
        155,
        156,
        157,
        158,
        159,
        160
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    },
    {
      "code": "698             Logs.info(f\"Command for documentation: {command}\")\n699             process = Popen(command, shell=True)  # nosec # nosemgrep\n700             process.communicate()\n",
      "filename": "WebScripts\\Pages.py",
      "issue_confidence": "HIGH",
      "issue_severity": "HIGH",
      "issue_text": "subprocess call with shell=True identified, security issue.",
      "line_number": 699,
      "line_range": [
        699
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true"
    },
    {
      "code": "62 from collections.abc import Callable\n63 from subprocess import Popen, PIPE  # nosec\n64 from types import SimpleNamespace\n",
      "filename": "WebScripts\\commons.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with Popen module.",
      "line_number": 63,
      "line_range": [
        63
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "445 \n446         process = Popen(\n447             [\n448                 r\"C:\\WINDOWS\\system32\\cmd.exe\",\n449                 \"/c\",\n450                 \"assoc\",\n451                 extension,\n452             ],  # protection against command injection\n453             stdout=PIPE,\n454             stderr=PIPE,\n455             text=True,\n456         )  # nosec\n",
      "filename": "WebScripts\\commons.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 446,
      "line_range": [
        446,
        447,
        448,
        449,
        450,
        451,
        452,
        453,
        454,
        455
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    },
    {
      "code": "462 \n463         process = Popen(\n464             [r\"C:\\WINDOWS\\system32\\cmd\", \"/c\", \"ftype\", filetype],\n465             stdout=PIPE,\n466             stderr=PIPE,\n467             text=True,\n468         )  # nosec\n",
      "filename": "WebScripts\\commons.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 463,
      "line_range": [
        463,
        464,
        465,
        466,
        467
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    },
    {
      "code": "1423             )\n1424             response = urlopen(  # nosec\n1425                 \"https://api.github.com/repos/mauricelambert/WebScripts/tags\"\n1426             )\n",
      "filename": "WebScripts\\hardening.py",
      "issue_confidence": "HIGH",
      "issue_severity": "MEDIUM",
      "issue_text": "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
      "line_number": 1424,
      "line_range": [
        1424,
        1425
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b310-urllib-urlopen",
      "test_id": "B310",
      "test_name": "blacklist"
    },
    {
      "code": "71 \n72     password_ = \"\"  # nosec\n73     key_length = len(key)\n",
      "filename": "WebScripts\\scripts\\passwords\\get_password_share.py",
      "issue_confidence": "MEDIUM",
      "issue_severity": "LOW",
      "issue_text": "Possible hardcoded password: ''",
      "line_number": 72,
      "line_range": [
        72
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html",
      "test_id": "B105",
      "test_name": "hardcoded_password_string"
    },
    {
      "code": "68 from os import path, _Environ, device_encoding, remove\n69 from subprocess import check_call, DEVNULL  # nosec\n70 from configparser import ConfigParser\n",
      "filename": "WebScripts\\utils.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with check_call module.",
      "line_number": 69,
      "line_range": [
        69
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "392 \n393     check_call(\n394         [\n395             r\"C:\\WINDOWS\\system32\\reg.exe\",\n396             \"add\",\n397             r\"HKEY_CURRENT_USER\\Console\",\n398             \"/v\",\n399             \"VirtualTerminalLevel\",\n400             \"/t\",\n401             \"REG_DWORD\",\n402             \"/d\",\n403             \"0x00000001\",\n404             \"/f\",\n405         ],\n406         stdout=DEVNULL,\n407         stderr=DEVNULL,\n408     )  # Active colors in console (for logs) # nosec\n",
      "filename": "WebScripts\\utils.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 393,
      "line_range": [
        393,
        394,
        395,
        396,
        397,
        398,
        399,
        400,
        401,
        402,
        403,
        404,
        405,
        406,
        407
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    }
  ]
}
```

### Semgrep

```txt
| versions          - semgrep 0.64.0 on Python 3.9.6
| environment       - running in environment github-actions, triggering event is 'push'
| manage            - not logged in
=== setting up agent configuration
| using semgrep rules from https://semgrep.dev/c/p/security-audit
| using semgrep rules from https://semgrep.dev/c/p/secrets
| using default path ignore rules of common test and dependency directories
| found 129 files in the paths to be scanned
| skipping 2 files based on path ignore rules
=== looking for current issues in 127 files
| 1 current issue found
| No ignored issues found
=== not looking at pre-existing issues since all files with current issues are newly created
python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
=== exiting with failing status
     > WebScripts/Pages.py:426
     ╷
  426│   process = Popen(command, shell=True)  # nosec
     ╵
     = Found 'subprocess' function 'Popen' with 'shell=True'. This is dangerous
       because this call will spawn the command using a shell process. Doing so
       propagates current shell settings and variables, which makes it much
       easier for a malicious actor to execute commands. Use 'shell=False'
       instead.
```

## DAST

```bash
zap-full-scan.py -t http://127.0.0.1:8000
```

```txt
Total of 54 URLs
PASS: Directory Browsing [0]
PASS: Vulnerable JS Library [10003]
PASS: Cookie No HttpOnly Flag [10010]
PASS: Cookie Without Secure Flag [10011]
PASS: Incomplete or No Cache-control Header Set [10015]
PASS: Cross-Domain JavaScript Source File Inclusion [10017]
PASS: Content-Type Header Missing [10019]
PASS: X-Frame-Options Header [10020]
PASS: X-Content-Type-Options Header Missing [10021]
PASS: Information Disclosure - Debug Error Messages [10023]
PASS: Information Disclosure - Sensitive Information in URL [10024]
PASS: Information Disclosure - Sensitive Information in HTTP Referrer Header [10025]
PASS: HTTP Parameter Override [10026]
PASS: Information Disclosure - Suspicious Comments [10027]
PASS: Open Redirect [10028]
PASS: Cookie Poisoning [10029]
PASS: User Controllable Charset [10030]
PASS: User Controllable HTML Element Attribute (Potential XSS) [10031]
PASS: Viewstate [10032]
PASS: Directory Browsing [10033]
PASS: Heartbleed OpenSSL Vulnerability (Indicative) [10034]
PASS: Strict-Transport-Security Header [10035]
PASS: Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) [10037]
PASS: Content Security Policy (CSP) Header Not Set [10038]
PASS: X-Backend-Server Header Information Leak [10039]
PASS: Secure Pages Include Mixed Content [10040]
PASS: HTTP to HTTPS Insecure Transition in Form Post [10041]
PASS: HTTPS to HTTP Insecure Transition in Form Post [10042]
PASS: User Controllable JavaScript Event (XSS) [10043]
PASS: Big Redirect Detected (Potential Sensitive Information Leak) [10044]
PASS: Source Code Disclosure - /WEB-INF folder [10045]
PASS: HTTPS Content Available via HTTP [10047]
PASS: Remote Code Execution - Shell Shock [10048]
PASS: Retrieved from Cache [10050]
PASS: Relative Path Confusion [10051]
PASS: X-ChromeLogger-Data (XCOLD) Header Information Leak [10052]
PASS: Apache Range Header DoS (CVE-2011-3192) [10053]
PASS: Cookie without SameSite Attribute [10054]
PASS: CSP [10055]
PASS: X-Debug-Token Information Leak [10056]
PASS: Username Hash Found [10057]
PASS: GET for POST [10058]
PASS: X-AspNet-Version Response Header [10061]
PASS: PII Disclosure [10062]
PASS: Backup File Disclosure [10095]
PASS: Timestamp Disclosure [10096]
PASS: Hash Disclosure [10097]
PASS: Cross-Domain Misconfiguration [10098]
PASS: User Agent Fuzzer [10104]
PASS: Weak Authentication Method [10105]
PASS: Httpoxy - Proxy Header Misuse [10107]
PASS: Reverse Tabnabbing [10108]
PASS: Modern Web Application [10109]
PASS: Absence of Anti-CSRF Tokens [10202]
PASS: Private IP Disclosure [2]
PASS: Anti-CSRF Tokens Check [20012]
PASS: HTTP Parameter Pollution [20014]
PASS: Heartbleed OpenSSL Vulnerability [20015]
PASS: Cross-Domain Misconfiguration [20016]
PASS: Source Code Disclosure - CVE-2012-1823 [20017]
PASS: Remote Code Execution - CVE-2012-1823 [20018]
PASS: External Redirect [20019]
PASS: Session ID in URL Rewrite [3]
PASS: Buffer Overflow [30001]
PASS: Format String Error [30002]
PASS: Integer Overflow Error [30003]
PASS: CRLF Injection [40003]
PASS: Parameter Tampering [40008]
PASS: Server Side Include [40009]
PASS: Cross Site Scripting (Reflected) [40012]
PASS: Session Fixation [40013]
PASS: Cross Site Scripting (Persistent) [40014]
PASS: Cross Site Scripting (Persistent) - Prime [40016]
PASS: Cross Site Scripting (Persistent) - Spider [40017]
PASS: SQL Injection [40018]
PASS: SQL Injection - MySQL [40019]
PASS: SQL Injection - Hypersonic SQL [40020]
PASS: SQL Injection - Oracle [40021]
PASS: SQL Injection - PostgreSQL [40022]
PASS: Possible Username Enumeration [40023]
PASS: SQL Injection - SQLite [40024]
PASS: Proxy Disclosure [40025]
PASS: Cross Site Scripting (DOM Based) [40026]
PASS: SQL Injection - MsSQL [40027]
PASS: ELMAH Information Leak [40028]
PASS: Trace.axd Information Leak [40029]
PASS: .htaccess Information Leak [40032]
PASS: .env Information Leak [40034]
PASS: Hidden File Finder [40035]
PASS: Source Code Disclosure - Git  [41]
PASS: Source Code Disclosure - SVN [42]
PASS: Source Code Disclosure - File Inclusion [43]
PASS: Script Active Scan Rules [50000]
PASS: Script Passive Scan Rules [50001]
PASS: Path Traversal [6]
PASS: Remote File Inclusion [7]
PASS: Insecure JSF ViewState [90001]
PASS: Charset Mismatch [90011]
PASS: XSLT Injection [90017]
PASS: Server Side Code Injection [90019]
PASS: Remote OS Command Injection [90020]
PASS: XPath Injection [90021]
PASS: XML External Entity Attack [90023]
PASS: Generic Padding Oracle [90024]
PASS: Expression Language Injection [90025]
PASS: SOAP Action Spoofing [90026]
PASS: Cookie Slack Detector [90027]
PASS: Insecure HTTP Method [90028]
PASS: SOAP XML Injection [90029]
PASS: WSDL File Detection [90030]
PASS: Loosely Scoped Cookie [90033]
PASS: Cloud Metadata Potentially Exposed [90034]
WARN-NEW: Server Leaks Version Information via "Server" HTTP Response Header Field [10036] x 10 
  http://127.0.0.1:8000/ (301 Moved Permanently)
  http://127.0.0.1:8000/web/ (200 OK)
  http://127.0.0.1:8000 (301 Moved Permanently)
  http://127.0.0.1:8000/robots.txt (301 Moved Permanently)
  http://127.0.0.1:8000/sitemap.xml (301 Moved Permanently)
WARN-NEW: HTTP Only Site [10106] x 1 
  http://127.0.0.1:8000 (0)
WARN-NEW: Application Error Disclosure [90022] x 1 
  http://127.0.0.1:8000/js/webscripts_script_js_scripts.js (200 OK)
FAIL-NEW: 0 FAIL-INPROG: 0  WARN-NEW: 3 WARN-INPROG: 0  INFO: 0 IGNORE: 0 PASS: 112
```