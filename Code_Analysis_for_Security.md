# Code Analysis for Security

## SAST

1. A vulnerability is found with: `Popen(..., shell=True, ...)` used for generating documentation. The vulnerability is not dangerous if the configrations files are protected by the system (rights and write permissions to these files).

### Bandit

```bash
bandit -i -l -r -v -f json -o "vulns.json" --ignore-nosec WebScripts
```

```json
{
  "errors": [],
  "generated_at": "2021-09-07T08:19:04Z",
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
      "loc": 525,
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
      "loc": 799,
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
      "loc": 26,
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
      "loc": 26,
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
      "loc": 732,
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
      "loc": 273,
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
      "loc": 89,
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
      "loc": 64,
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
      "loc": 75,
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
      "loc": 61,
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
      "loc": 49,
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
      "loc": 42,
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
      "loc": 40,
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
      "loc": 41,
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
      "loc": 304,
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
      "loc": 63,
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
      "loc": 67,
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
      "loc": 54,
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
      "loc": 81,
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
      "loc": 121,
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
      "loc": 122,
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
      "loc": 32,
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
      "loc": 26,
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
      "loc": 58,
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
      "loc": 11,
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
      "loc": 61,
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
      "loc": 47,
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
      "loc": 50,
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
      "loc": 42,
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
      "loc": 40,
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
      "loc": 55,
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
      "loc": 55,
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
      "loc": 43,
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
      "loc": 52,
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
      "loc": 56,
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
      "loc": 230,
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
      "loc": 92,
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
      "loc": 442,
      "nosec": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 8.0,
      "CONFIDENCE.LOW": 0.0,
      "CONFIDENCE.MEDIUM": 1.0,
      "CONFIDENCE.UNDEFINED": 0.0,
      "SEVERITY.HIGH": 1.0,
      "SEVERITY.LOW": 8.0,
      "SEVERITY.MEDIUM": 0.0,
      "SEVERITY.UNDEFINED": 0.0,
      "loc": 5273,
      "nosec": 0
    }
  },
  "results": [
    {
      "code": "28 \n29 from subprocess import Popen, PIPE, TimeoutExpired\n30 from typing import Tuple, List, Dict\n",
      "filename": "WebScripts\\Pages.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with Popen module.",
      "line_number": 29,
      "line_range": [
        29
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "135     process = Popen(\n136         arguments, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False, env=script_env\n137     )\n138 \n",
      "filename": "WebScripts\\Pages.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 136,
      "line_range": [
        135,
        136
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    },
    {
      "code": "425             Logs.info(f\"Command for documentation: {command}\")\n426             process = Popen(command, shell=True)\n427             process.communicate()\n",
      "filename": "WebScripts\\Pages.py",
      "issue_confidence": "HIGH",
      "issue_severity": "HIGH",
      "issue_text": "subprocess call with shell=True identified, security issue.",
      "line_number": 426,
      "line_range": [
        426
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true"
    },
    {
      "code": "31 from collections.abc import Callable\n32 from subprocess import Popen, PIPE\n33 from types import SimpleNamespace\n",
      "filename": "WebScripts\\commons.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with Popen module.",
      "line_number": 32,
      "line_range": [
        32
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "403 \n404         process = Popen(\n405             [r\"C:\\WINDOWS\\system32\\cmd.exe\", \"/c\", \"assoc\", extension], stdout=PIPE, stderr=PIPE, text=True\n406         )\n",
      "filename": "WebScripts\\commons.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 404,
      "line_range": [
        404,
        405
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    },
    {
      "code": "412 \n413         process = Popen(\n414             [r\"C:\\WINDOWS\\system32\\cmd\", \"/c\", \"ftype\", filetype], stdout=PIPE, stderr=PIPE, text=True\n415         )\n",
      "filename": "WebScripts\\commons.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 413,
      "line_range": [
        413,
        414
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    },
    {
      "code": "69 \n70     password_ = \"\"\n71     key_length = len(key)\n",
      "filename": "WebScripts\\scripts\\passwords\\get_password_share.py",
      "issue_confidence": "MEDIUM",
      "issue_severity": "LOW",
      "issue_text": "Possible hardcoded password: ''",
      "line_number": 70,
      "line_range": [
        70
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html",
      "test_id": "B105",
      "test_name": "hardcoded_password_string"
    },
    {
      "code": "32 from os import path, _Environ, device_encoding\n33 from subprocess import check_call, DEVNULL\n34 from configparser import ConfigParser\n",
      "filename": "WebScripts\\utils.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with check_call module.",
      "line_number": 33,
      "line_range": [
        33
      ],
      "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "335 \n336     check_call([r\"C:\\WINDOWS\\system32\\reg.exe\", \"add\", r\"HKEY_CURRENT_USER\\Console\", \"/v\", \"VirtualTerminalLevel\", \"/t\", \"REG_DWORD\", \"/d\", \"0x00000001\", \"/f\"], stdout=DEVNULL, stderr=DEVNULL) # Active colors in console (for logs)\n337 \n",
      "filename": "WebScripts\\utils.py",
      "issue_confidence": "HIGH",
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 336,
      "line_range": [
        336
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

DAST tests are coming.