# File share

[Code documentation](https://mauricelambert.github.io/info/python/code/WebScripts/uploads_management.html)

## In Server scripts

### Add file

Using data string with default option values:

```python
from WebScripts.scripts.uploads.modules.uploads_management import (
    Upload,
    write_file,
    get_visible_files,
)
from typing import List

write_file(
    "\x00string content\xff", # file content, if is binary you can use base64 or decode it with latin-1
    "my_filename.txt",        # File name
    0,                        # Read access (0 == everyone can read it)
    0,                        # Write access (0 == everyone can write it)
    0,                        # Delete access (0 == everyone can delete it)
    False,                    # Hidden (if False, this file will be visible to other authenticated users)
    False,                    # Is binary
    True,                     # Compress the file
    False,                    # Is encoded as Base64
    with_access = True,       # Check access to write this file (some scripts should write a file with an unauthenticated user)
)                             # Write a new file named "my_filename.txt"

filenames: List[str] = []
for file in get_visible_files():
    assert isinstance(file, Upload)
    filenames.append(file.name)

assert "my_filename.txt" in filenames
# file is not hidden and not deleted
```

Using base64 data with hidden option and binary option:

```python
from WebScripts.scripts.uploads.modules.uploads_management import (
    write_file,
    get_visible_files,
)
from base64 import b64decode, b64encode
from typing import List

content2 = b64encode(b'\x00version 2\xff').decode()

write_file(
    content2,                 # file content, if is binary you can use base64 or decode it with latin-1
    "my_filename.txt",        # File name
    0,                        # Read access (0 == everyone can read it)
    1000,                     # Write access (1000 == Admin can write it)
    1000,                     # Delete access (1000 == Admin can delete it)
    True,                     # Hidden
    True,                     # Is binary
    True,                     # Compress the file
    True,                     # Is encoded as Base64
    with_access = False,      # Check access to write this file (some scripts should write a file with an unauthenticated user)
)                             # Write a new version of this file

filenames: List[str] = []
for file in get_visible_files():
    filenames.append(file.name)

assert "my_filename.txt" not in filenames
# file is hidden
```

### Get a file

```python
from WebScripts.scripts.uploads.modules.uploads_management import (
    get_file,
)

versions, counter = get_file("my_filename.txt")
assert len(versions) == 2
assert counter["my_filename.txt"] == 2
```

### Read a file

With verification of permissions:

```python
assert b64decode(read_file("my_filename.txt").encode()) == b"\x00version 2\xff"
# the read_file function checks permissions
```

Without verification of permissions:

```python
data, filename = get_file_content(name="my_filename.txt")
assert b64decode(data.encode()) == b"\x00version 2\xff"
# the get_file_content don't checks permissions, you should use it for Admin access ONLY
```

### Delete a file

On WebScripts server a file is **never deleted on the disk**, for security reason you can't delete a file from the WebScripts interface (it's useful for *Forensics*, *Investigations* or *Incident Response* on a WebScripts compromission).

```python
delete_file("my_filename.txt")

try:
    get_file_content(name="my_filename.txt")
    read_file("my_filename.txt")
except FileNotFoundError:
    pass
# a deleted file cannot be read using the file name
```

### Read a file using its ID

This feature allow **administrator only** to read any version of uploaded file and deleted file.

```python
data, filename = get_file_content(id_="1")
assert b64decode(data.encode()) == b"\x00string content\xff"
# the function get_file_content can read an old version (and a deleted file)
```

## API Client

### Recommendation

The `get_any_file.py` script work for small files, but I don't recommend using it for large files as these scripts take a lot of time and require a lot of memory.

I wrote a new module (in WebScripts version: `2.3.0`) to upload and download the files more easily from the script or command line. This module sends compressed content from the file (using GZIP), the file name is at the end of the URL, and options must be sent as *HTTP headers*.

You can easily use the download function in a web browser using `get_file.py`, for uploading, use the `upload_file.py` script.

#### Download

 - URL: `http://127.0.0.1:8000/share/Download/filename/<filename>`

```python
from urllib.request import urlopen, Request
from base64 import b64encode
from gzip import decompress

def get_basic_auth(username: str, password: str) -> str:
    return b64encode(f"{username}:{password}".encode()).decode()

# Uncompressed file (file are compressed by default)
with open("my_filename.txt", "wb") as file:
    file.write(urlopen(
        Request(
            "http://127.0.0.1:8000/share/Download/filename/my_filename.txt",
            headers={
                "Authorization": f"Basic {get_basic_auth('Admin', 'Admin')}",
                # Credentials are the base64 of '<username>:<password>'.
                # Get it in python with: get_basic_auth("Admin", "Admin") == "QWRtaW46QWRtaW4=".
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1:8000",
            },
        ),
    ).read())

# Compressed file (file are compressed by default)
with open("my_filename.txt", "wb") as file:
    file.write(decompress(urlopen(
        Request(
            "http://127.0.0.1:8000/share/Download/filename/my_filename.txt",
            headers={
                "Authorization": f"Basic {get_basic_auth('Admin', 'Admin')}",
                # Credentials are the base64 of '<username>:<password>'.
                # Get it in python with: get_basic_auth("Admin", "Admin") == "QWRtaW46QWRtaW4=".
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1:8000",
            },
        ),
    ).read()))
```

#### Upload

 - URL: `http://127.0.0.1:8000/share/upload/<filename>`
 - Boolean Options (as HTTP headers):
     - `No-Compression`
     - `Is-Base64`
     - `Hidden`
     - `Binary`
 - Integer Options (as HTTP headers):
     - `Read-Permission`
     - `Write-Permission`
     - `Delete-Permission`

Without options:

```python
from urllib.request import urlopen, Request

with open("my_filename.txt", 'rb') as file:
    urlopen(
        Request(
            "http://127.0.0.1:8000/share/upload/my_filename.txt",
            headers={
                "Authorization": "Basic QWRtaW46QWRtaW4=",
                # Credentials are the base64 of '<username>:<password>'.
                # Get it in python with: get_basic_auth("Admin", "Admin") == "QWRtaW46QWRtaW4=".
                "Content-Type": "application/octet-stream",
                "Origin": "http://127.0.0.1:8000",
            },
            data=file.read(),
            method="POST",
        ),    
    )
```

Using all options:

```python
from urllib.request import urlopen, Request
from base64 import b64encode

with open("my_filename.txt", 'rb') as file:
    urlopen(
        Request(
            "http://127.0.0.1:8000/share/upload/my_filename.txt",
            headers={
                "Authorization": "Basic QWRtaW46QWRtaW4=",
                # Credentials are the base64 of '<username>:<password>'.
                # Get it in python with: get_basic_auth("Admin", "Admin") == "QWRtaW46QWRtaW4=".
                "No-Compression": "yes",     # The value does not matter as long as the value 'No-Compression' is not empty
                "Is-Base64": "1",            # The value does not matter as long as the value 'Is-Base64' is not empty
                "Hidden": "0",               # The value does not matter as long as the value 'Hidden' is not empty
                "Binary": "no",              # The value does not matter as long as the value 'Binary' is not empty
                "Read-Permission": "0",      # The value must be an integer otherwise you will get an error 500
                "Write-Permission": "1000",  # The value must be an integer otherwise you will get an error 500
                "Delete-Permission": "1000", # The value must be an integer otherwise you will get an error 500
                "Content-Type": "application/octet-stream",
                "Origin": "http://127.0.0.1:8000",
            },
            data=b64encode(file.read()),
            method="POST",
        ),
    )
```

### Console client

#### Linux

##### Download

```bash
curl -u 'Admin:Admin' http://127.0.0.1:8000/share/Download/filename/LICENSE.txt                                # for uncompressed file
curl -u 'Admin:Admin' http://127.0.0.1:8000/share/Download/filename/file.text --output - | gzip -d > file.txt  # for compressed file
```

##### Upload

```bash
curl -u 'Admin:Admin' -H "Origin: http://127.0.0.1:8000" -d 'data' http://127.0.0.1:8000/share/upload/file.txt

curl -H "Origin: http://127.0.0.1:8000" -H 'No-Compression: yes' -H 'Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin' --data "@file.tar.gz" "http://127.0.0.1:8000/share/upload/file.tar.gz" >&1

## Deployed WebScripts (with HTTPS and self signed certificate)

curl --insecure -H "Origin: http://127.0.0.1:8000" -H 'Is-Base64: yes' -H 'No-Compression: yes' -H 'Api-Key: AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin' --data "$(cat file.txt | base64)" "https://webscripts.local/share/upload/file.txt"
```

#### Windows Powershell

##### Download

```powershell
[System.Text.Encoding]::ASCII.GetString((Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4="; Origin = "http://127.0.0.1:8000" } -Uri "http://127.0.0.1:8000/share/Download/filename/file.txt").Content) | Out-File -FilePath .\file.txt
```

##### Upload

```powershell
Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4="; Origin = "http://127.0.0.1:8000" } -Method 'Post' -Body 'data' -Uri http://127.0.0.1:8000/share/upload/file.txt
Invoke-WebRequest -Headers @{ Authorization = "Basic QWRtaW46QWRtaW4="; Origin = "http://127.0.0.1:8000" } -Method 'Post' -Body $(Get-Content file.txt) -Uri http://127.0.0.1:8000/share/upload/file.txt
```
