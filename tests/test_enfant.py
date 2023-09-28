from os import environ, system
from time import sleep

sleep(1)
test = environ.get("Test")
system("echo %Test%")
print(f"test_enfant.py: {test}")
assert test is not None
input("End test_enfant.py...")
