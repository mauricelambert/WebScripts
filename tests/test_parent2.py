from subprocess import run, Popen, PIPE
from threading import Thread
from os import environ

environ1 = {**environ}
environ2 = {**environ}  # if not environ in env: Python fatal error
environ1["Test"] = "Yes test is good !"
environ2["Test"] = "No is not good !"

# Thread(target=run, args=(["python", "test_enfant.py"],), kwargs={"env": environ1}).start()
process = Popen(["python", "test_enfant2.py"], stdin=PIPE, env=environ2)
process.communicate(input=b"a" * 70000 + b"\na\na\na\xf4\xc3\xb4")
