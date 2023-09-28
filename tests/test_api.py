from urllib.request import urlopen, Request, HTTPError, URLError
from ssl import _create_unverified_context
from pprint import pprint
from json import load

###
# JSON RPC
###

try:
    response = urlopen(
        Request(
            "http://127.0.0.1:8000/JsonRpc/JsonRpc/",
            method="POST",
            headers={"Authorization": "Basic QWRtaW46QWRtaW4="},
            data=b'{"jsonrpc": "2.0", "id": 4, "method": "not"}',
        )
    )
except (HTTPError, URLError) as e:
    response = e

print("Status", response.code, response.reason)
pprint(load(response))

try:
    response = urlopen(
        Request(
            "http://127.0.0.1:8000/JsonRpc/JsonRpc/call",
            method="POST",
            headers={"Origin": "http://127.0.0.1:8000", "Authorization": "Basic QWRtaW46QWRtaW4=", "Content-Type": "application/json"},
            data=b'{"jsonrpc": "2.0", "id": 1, "method": "call"}',
        )
    )
except (HTTPError, URLError) as e:
    response = e

print("Status", response.code, response.reason)
pprint(load(response))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/JsonRpc/JsonRpc/test_argument_list",
        method="POST",
        headers={"Origin": "http://127.0.0.1:8000", "Authorization": "Basic QWRtaW46QWRtaW4=", "Content-Type": "application/json"},
        data=b'{"jsonrpc": "2.0", "id": 2, "method": "test_argument_list", "params": ["abc", 1, null, true]}',
    )
)
pprint(load(response))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/JsonRpc/JsonRpc/test_args_dict",
        method="POST",
        headers={"Origin": "http://127.0.0.1:8000", "Authorization": "Basic QWRtaW46QWRtaW4=", "Content-Type": "application/json"},
        data=b'{"jsonrpc": "2.0", "id": 3, "method": "test_args_dict", "params": {"a": 2, "b": 3}}',
    )
)
pprint(load(response))

exit()

###
# IP Spoofing
###

response = urlopen(
    Request(
        "https://127.0.0.1/api/",
        method="GET",
        headers={
            "X-Forwarded-For": "0.0.0.0",
            "Client-Ip": "1.1.1.1",
        },
    ),
    context=_create_unverified_context(),
)
pprint(loads(response.read()))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/",
        method="GET",
        headers={
            "X-Forwarded-For": "0.0.0.0",
            "Client-Ip": "1.1.1.1",
        },
    )
)
pprint(loads(response.read()))

exit()

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py",
        method="POST",
        headers={
            "Api-Key": "AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin",
        },
    )
)
pprint(loads(response.read()))

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py",
        method="POST",
        headers={"Authorization": "Basic QWRtaW46QWRtaW4="},
        data=b'{"arguments":{"--ids":{"value":[2],"input":false}}}',
    )
)
pprint(loads(response.read()))
exit()

for a in range(5):
    try:
        response = urlopen(
            Request(
                "http://127.0.0.1:8000/api/scripts/password_generator.py",
                method="POST",
                headers={"Authorization": "Basic VGVzdDp0ZXN0"},
            )
        )
        print(f"{a}. 200 OK Test")
    except Exception as e:
        assert e.status == 403

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py",
        method="POST",
        headers={"Authorization": "Basic QWRtaW46QWRtaW4="},
    )
)
assert response.status == 200
print("1. 200 OK Admin")

response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/view_users.py",
        method="POST",
        headers={
            "Api-Key": "AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin"
        },
    )
)
assert response.status == 200
print("2. 200 OK Admin")
