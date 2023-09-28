from os import system, environ
from threading import Thread

environ["Test"] = "Yes test is good !"
print(f"test_parent.py: {environ.get('Test')}")
Thread(target=system, args=("test_enfant.py",)).start()
environ["Test"] = "No is not good !"
system("test_enfant2.py")
