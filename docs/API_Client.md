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

## Upload client

For more details and other examples, see the [sharing documentation](https://webscripts.readthedocs.io/en/latest/File_Share/) ([wiki](https://github.com/mauricelambert/WebScripts/wiki/File-Share)).

### Linux

#### Download
```bash
curl -u 'Admin:Admin' http://127.0.0.1:8000/share/Download/filename/file.extension --output - | gzip -d > file.extension
```

#### Upload
```bash
curl -u 'Admin:Admin' -d 'data' http://127.0.0.1:8000/share/upload/file.extension

curl -H 'No-Compression: yes' -H 'Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin' --data "@file.tar.gz" "http://127.0.0.1:8000/share/upload/file.tar.gz" >&1

## Deployed WebScripts (with HTTPS and self signed certificate)

curl --insecure -H 'Is-Base64: yes' -H 'No-Compression: yes' -H 'Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin' --data "$(cat file.txt | base64)" "https://webscripts.local/share/upload/file.txt" >&1
```

### Windows

#### Download
```bash
[System.Text.Encoding]::ASCII.GetString((Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4=" } -Uri "http://127.0.0.1:8000/share/Download/filename/file.extension").Content) | Out-File -FilePath .\file.extension
```

#### Upload
```bash
Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4=" } -Method 'Post' -Body 'data' -Uri http://127.0.0.1:8000/share/upload/file.extension
```

## Real Time Output

Force to flush the output is required after `print`, `echo`...

1. In Python scripts, add this two lines on the top of the script:

```python
from functools import partial
print=partial(print, flush=True)
```

alternately, you can add the flush argument on all of the `print` calls:

```python
print("first call", flush=True)
print("second call", flush=True)
...
```

or use `sys.stdout.flush`:

```python
import sys
print("first call")
sys.stdout.flush()
sys.stdout.write("second call\n")
sys.stdout.flush()
...
```

2. In Bash scripts, there is no impact.
3. In PHP scripts, call the `flush` function after `echo`:

```php
echo "first call";
flush();
echo "second call";
flush();
```

4. In Ruby scripts, add this line on the top of the script:

```ruby
$stdout.sync = true
```

alternately, call the `$stdout.flush` function after `$stdout.print` or `puts` or `print`:

```ruby
$stdout.print "first call"
$stdout.flush
puts "second call"
$stdout.flush
print "third call"
$stdout.flush
```

5. In Perl scripts, add this line on the top of the script:

```perl
local $| = 1;
```

or

```perl
STDOUT->autoflush(1)
```

alternately, call `select()->flush` function after `print`:

```perl
print "first call";
select()->flush();
print "second call";
select()->flush();
```