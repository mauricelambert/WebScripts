# Default Database

## Files

 - `data/users.csv`: Users database for authentication
 - `data/groups.csv`: Groups database for permissions and access
 - `data/passwords.csv`: temp passswords share
 - `data/id`: the last ID for temp passwords share
 - `data/uploads.csv`: versions and actions of uploaded files

Delimiter is `,` and quote is `"`.

## Users

The users database columns:
 1. ID: the unique ID of the user
 2. name: the unique name of the user
 3. password: base64 password hash (SHA512 using `hashlib.pbkdf2_hmac`)
 4. salt: Salt for password hash. Generation of 32 random bytes using `secrets.token_bytes(32)`.
 5. enumerations: Enumerations for password hash. Generation of number between: *90000* and *110000* using `90000 + secrets.randbelow(20000)`.
 6. IPs: List of authorized IPs using glob syntax.
 7. groups: List of group IDs for user permissions and access.
 8. apikey: The API key for authenticating users using a API client. It is the base64 of 125 random bytes (`base64.b64encode(secrets.token_bytes(125))`).

## Groups

The groups database columns:
 1. ID: the unique ID of the group and the permission level
 2. name: the unique name of the group

## Passwords

The passwords database columns:
 1. timestamp: The timestamp (a float) of the max time to view the password.
 2. password: Encrypted password (using XOR, the key and the salt is 60 random bytes using `secrets.token_bytes(60)`)
 3. views: The number of views remaining
 4. hash: Hexadecimal of the password hash (SHA512 using `hashlib.pbkdf2_hmac`)
 5. iteration: Random integer between *9999* and *15000* using `random.randint(9999, 15000)`
 6. ID: The unique ID of the password

Passwords are automatically deleted when they expire.

## Uploads

The uploads database columns:
 1. ID: the action ID (an auto-incremented integer)
 2. name: the name of the file
 3. read_permission: permission required to read this file
 4. write_permission: permission required to write this file
 5. delete_permission: permission required to delete this file
 6. hidden: hide file (only admin can see the file), you can read, write and delete the file if you know the name
 7. is_deleted: status ("deleted" or "exist") (administrators can see deleted files)
 8. is_binary: state ("binary" or "text")
 9. timestamp: time of this action (a float)
 10. user: the "owner" of the file (the user of this action)
 11. version: the version of the file

### Using uploads in python script

```python
from WebScripts.scripts.uploads.modules.uploads_management import (
    Upload, 
    get_file, 
    read_file, 
    write_file, 
    delete_file, 
    get_file_content, 
    get_visible_files,
)
from base64 import b64decode, b64encode

write_file(
    "\x00string content\xff", # if is binary you can use base64 ou decode it with latin-1
    "my_filename.txt",        # File name
    0,                        # Read access (0 == everyone can read it)
    0,                        # Write access (0 == everyone can write it)
    0,                        # Delete access (0 == everyone can delete it)
    False,                    # Hidden (if False, this file will be visible to other authenticated users)
    False,                    # Is binary
    False,                    # Is encoded as Base64
    with_access = True,       # Check access to write this file (some scripts should write a file with an unauthenticated user)
)                             # Write a new file named "my_filename.txt"

content2 = b64encode(b'\x00version 2\xff').decode()

filenames: List[str] = []
for file in get_visible_files():
    assert isinstance(file, Upload)
    filenames.append(file.name)

assert "my_filename.txt" in filenames
# file is not hidden and not deleted

write_file(
    content2,                 # if is binary you can use base64 ou decode it with latin-1
    "my_filename.txt",        # File name
    0,                        # Read access (0 == everyone can read it)
    1000,                     # Write access (1000 == Admin can write it)
    1000,                     # Delete access (1000 == Admin can delete it)
    True,                     # Hidden
    True,                     # Is binary
    True,                     # Is encoded as Base64
    with_access = False,      # Check access to write this file (some scripts should write a file with an unauthenticated user)
)                             # Write a new version of this file

filenames: List[str] = []
for file in get_visible_files():
    filenames.append(file.name)

assert "my_filename.txt" not in filenames
# file is hidden

versions, counter = get_file("my_filename.txt")
assert len(versions) == 2

assert b64decode(read_file("my_filename.txt").encode()) == b"\x00version 2\xff"
# read_file check access

data, filename = get_file_content(name="my_filename.txt")
assert b64decode(data.encode()) == b"\x00version 2\xff"
# get_file_content don't check access

delete_file("my_filename.txt")

try:
    get_file_content(name="my_filename.txt")
    read_file("my_filename.txt")
except FileNotFoundError:
    pass
# a deleted file can't be read using the filename

data, filename = get_file_content(id_="1")
assert b64decode(data.encode()) == b"\x00string content\xff"
# get_file_content can read an old version (and deleted file)
```

## Default database

users.csv
```csv
ID,name,password,salt,enumerations,IPs,groups,apikey
0,Not Authenticated,,,,*,0,
1,Unknow,,,,*,"0,1",
2,Admin,pZo8c8+cKLTHFaUBxGwcYaFDgNRw9HHph4brixOo6OMusFKbfkBEObZiNwda/f9W3+IpiMY8kqiFmQcbkUCbGw==,c2FsdA==,1000,"192.168.*,172.16.*,10.*,127.0.*","50,1000",AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin

```

groups.csv
```csv
ID,name
0,Not Authenticated
1,Unknow
50,User
500,Developers
750,Maintainers
1000,Administrators

```

To reset it:
```bash
python3 scripts/account/modules/manage_defaults_databases.py
```