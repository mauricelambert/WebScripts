# Users access and rights

## Script configurations

You can combine the different configurations.

### Minimum access

The easiest way to manage access on a script is the **script configuration** `minimum_access`.

Example:

 - The group ID for the `User` group (default group for the authenticated users) is `50`. To add a script for the authenticated users add this configuration: `minimum_access=50` (INI syntax) or `"minimum_access": 50` (JSON syntax).
    1. A simple user with this list of group ID: `0,1,50` will get access on the added script because the greater access of the user is `50` (>= 50).
    2. A not authenticated user (with this list of group ID: `0`) don't have permissions to access to the new script.
    3. A administrator user with this list of group ID: `1000,1001` will get access on the added script because the greater access of the user is `1001` (>= 50).

### Specific group

You cannot use the `minimum_access` for an administration script because you can add a `SOC` group with ID `1001` and SOC users should not have access to administrative scripts.

To add a script with specific group access you should use the **script configuration** `access_groups`.

Example:

 - The group ID for the `Administrators` group is `1000`, for this example the group ID for the `SOC` is `1001`. To add a script for the administrators and SOC users add this configuration: `access_groups=1000,1001` (INI syntax) or `"access_groups": [1000,1001],` (JSON syntax).
    1. A administror user with this list of group ID: `0,1,50,1000` will get access on the added script because `1000` is in the list.
    2. A SOC user with this list of group ID: `1001` will get access on the added script because `1001` is in the list.
    3. A manager user with this list of group ID: `1002` don't have permissions to access to the new script.

### Specific user

Sometimes a user not in the access group need to access to the script. To add a script with specific user access you shold use the **script configuration** `access_users`.

Example:

 - The user ID for the `Admin` user is `2`. To add a script for the `Admin` user add this configuration: `access_users=2` (INI syntax) or `"access_users": [2]` (JSON syntax).
    1. Only the `Admin` user have the user ID `2` and access to the new script.

## User permissions

Somes users should not access to all normal scripts (for example a generic user for `SupportX` teams).

Users have a list of glob syntax for script names and a list of glob syntax for categories. If the script category match with any glob syntax for categories or the script name match with any glob syntax for script names the user get the access on this script.

The `SupportX` user with this list of glob syntax for categories `["*Account*", "*License*"]` and this list of glob syntax for script names `["*password*"]` can access to this default scripts: 

 1. Authentication
    - `/auth/`: The auth script is always accessible for everyone.
 2. License
    - `show_license.py`: The categories `License` match with `*License*`.
 3. My Account
    - `change_my_password.py`: The script name `change_my_password.py` match with `*password*` and the `My Account` category match with `*Account*`.
    - `get_apikey.py`: The `My Account` category match with `*Account*`
 4. Password
    - `password_generator.py`: The script name `password_generator.py` match with `*password*`.
    - `get_password_share.py`: The script name `get_password_share.py` match with `*password*`.
    - `new_password_share.py`: The script name `new_password_share.py` match with `*password*`.

## Share: upload and download permissions

Three permissions exists on the default file share:

 1. *Read* permission: download the file
 2. *Write* permission: write a new version of the file
     - **caution**: with write permission, the user can change all permissions on this file.
 3. *Delete* permission: delete the file (the administrator can see all versions of the file)

Permissions are a number (a group ID), to access a file a user needs a group ID greater than or equal to the permission.