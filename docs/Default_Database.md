# Default Database

## Files

 - `data/users.csv`: Users database for authentication
 - `data/groups.csv`: Groups database for permissions and access
 - `data/passwords.csv`: temp passswords share
 - `data/id`: the last ID for temp passwords share
 - `data/uploads.csv`: versions and actions of uploaded files
 - `data/requests.csv`: user requests or reports

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
 5. iteration: Random integer between *9999* and *15000* using `9999 + secrets.randbelow(5001)`
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

## Requests

The requests database columns:

 1. ID: the request ID (an auto-incremented integer)
 2. Time: timestamp of request creation
 3. UserName: user name used to create the request
 4. ErrorCode: the HTTP error code page used to create the request
 5. Page: URL used to create the request
 6. UserAgent: the UserAgent used to create the request
 7. Subject: subject of the request
 8. Reason: reason of the request
 9. Name: the name of the person creating the request

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