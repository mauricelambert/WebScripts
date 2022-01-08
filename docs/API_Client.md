# API Client

## WebScriptsClient

I developed a WebScripts client in Python with a CLI (command-line tool). I recommend using it for advanced uses.

##### Features implemented:

 - Get scripts, arguments and informations
 - Execute scripts on WebScripts Server (simple script output + real time script output)
 - Download file from WebScripts Server
 - Upload file on WebScripts Server
 - Send requests or reports to WebScripts Administrator
 - Test the WebScripts Server

##### Examples

Examples are available in the [README.md](https://github.com/mauricelambert/WebScriptsClient/blob/main/README.md#usages) and the [documentation](https://mauricelambert.github.io/info/python/code/WebScriptsClient.html) (Python examples and CLI).

##### Links:

 - [WebScriptsClient on github](https://github.com/mauricelambert/WebScriptsClient)
 - [WebScriptsClient on pypi](https://pypi.org/project/WebScriptsClient/)
 - [WebScriptsClient documentation](https://mauricelambert.github.io/info/python/code/WebScriptsClient.html)
 - [WebScriptsClient executable](https://mauricelambert.github.io/info/python/code/WebScriptsClient.pyz)

## Using CURL

```bash
curl -u 'Admin:Admin' -H "Content-Type: application/json" -H "Origin: http://127.0.0.1:8000" -d '{"arguments":{"length":{"value":"10","input":false},"CRITICAL":{"value":true,"input":false}}}' http://127.0.0.1:8000/api/scripts/log_viewer.py
```

Response:
```json
{"stdout": "<critical logs>", "stderr": "", "code": 0, "Content-Type": "text/plain", "error": "No errors"}
```

## Using python

```python
from urllib.request import urlopen, Request
from pprint import pprint
from json import loads

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py",
        method="POST",
        headers={
            "Api-Key": "AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin",
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8000",
        }
    )
)
pprint(loads(response.read()))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py", 
        method="POST", 
        headers={
            "Authorization": "Basic QWRtaW46QWRtaW4=",  # from base64 import b64encode; f"Basic {b64encode(b'Admin:Admin').decode()}"
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8000",
        },
        data=b'{"arguments":{"--ids":{"value":[2],"input":false}}}',
    )
)
pprint(loads(response.read()))
```

```python
{'Content-Type': 'text/html',
 'code': 0,
 'error': 'No errors',
 'stderr': '',
 'stdout': '<table>\r\n'
           '<tr><td>ID</td><td>name</td><td>IPs</td><td>groups</td><td>apikey</td></tr>\r\n'
           '<tr><td>0</td><td>Not '
           'Authenticated</td><td>*</td><td>0</td><td></td></tr>\r\n'
           '<tr><td>1</td><td>Unknow</td><td>*</td><td>0,1</td><td></td></tr>\r\n'
           '<tr><td>2</td><td>Admin</td><td>192.168.*,172.16.*,10.*,127.0.*</td><td>50,1000</td><td>AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin</td></tr>\r\n'
           '</table>\r\n'}
{'Content-Type': 'text/html',
 'code': 0,
 'error': 'No errors',
 'stderr': '',
 'stdout': '<table>\r\n'
           '<tr><td>2</td><td>Admin</td><td>192.168.*,172.16.*,10.*,127.0.*</td><td>50,1000</td><td>AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin</td></tr>\r\n'
           '</table>\r\n'}
```

## Upload client

For more details and other examples, see the [sharing documentation](https://webscripts.readthedocs.io/en/latest/File_Share/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/File-Share)).

### Linux

#### Download
```bash
curl -u 'Admin:Admin' http://127.0.0.1:8000/share/Download/filename/LICENSE.txt                                # for uncompressed file
curl -u 'Admin:Admin' http://127.0.0.1:8000/share/Download/filename/file.text --output - | gzip -d > file.txt  # for compressed file
```

#### Upload
```bash
curl -u 'Admin:Admin' -H "Origin: http://127.0.0.1:8000" -d 'data' http://127.0.0.1:8000/share/upload/file.txt

curl -H "Origin: http://127.0.0.1:8000" -H 'No-Compression: yes' -H 'Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin' --data "@file.tar.gz" "http://127.0.0.1:8000/share/upload/file.tar.gz" >&1

## Deployed WebScripts (with HTTPS and self signed certificate)

curl --insecure -H "Origin: http://127.0.0.1:8000" -H 'Is-Base64: yes' -H 'No-Compression: yes' -H 'Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin' --data "$(cat file.txt | base64)" "https://webscripts.local/share/upload/file.txt"
```

### Windows

#### Download
```bash
[System.Text.Encoding]::ASCII.GetString((Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4="; Origin = "http://127.0.0.1:8000" } -Uri "http://127.0.0.1:8000/share/Download/filename/file.txt").Content) | Out-File -FilePath .\file.txt
```

#### Upload
```bash
Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4="; Origin = "http://127.0.0.1:8000" } -Method 'Post' -Body 'data' -Uri http://127.0.0.1:8000/share/upload/file.txt
Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4="; Origin = "http://127.0.0.1:8000" } -Method 'Post' -Body $(Get-Content file.txt) -Uri http://127.0.0.1:8000/share/upload/file.txt
```
