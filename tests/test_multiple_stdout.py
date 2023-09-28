from urllib.request import urlopen, Request
from pprint import pprint
from json import loads, dumps
from time import time, sleep

start = time()
response = urlopen(
    Request(
        "http://127.0.0.1:8000/api/scripts/test_config.py",
        method="POST",
        headers={
            "Api-Key": "AdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdminAdmin",
        },
        data=dumps(
            {
                "arguments": {
                    "test_i": {"value": "Admin", "input": True},
                    "select": {"value": "select", "input": False},
                    "--timeout": {"value": True, "input": False},
                    "password": {"value": ["Admin"], "input": False},
                    "select-input": {"value": "select", "input": True},
                }
            }
        ).encode(),
    )
)
data = loads(response.read())
print(time() - start)
pprint(data)

while "key" in data:
    response = urlopen(
        Request(
            f"http://127.0.0.1:8000/api/script/get/{data['key']}",
            method="GET",
            headers={"Authorization": "Basic QWRtaW46QWRtaW4="},
        )
    )
    data = loads(response.read())
    print(time() - start)
    pprint(data)
