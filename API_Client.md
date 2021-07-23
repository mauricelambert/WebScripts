# API Client

## Using CURL

```bash
curl -u 'Admin:Admin' -d '{"arguments":{"length":{"value":"10","input":false},"CRITICAL":{"value":true,"input":false}}}' http://127.0.0.1:8000/api/scripts/log_viewer.py
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
        }
    )
)
pprint(loads(response.read()))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py", 
        method="POST", 
        headers={
            "Authorization": "Basic QWRtaW46QWRtaW4="
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