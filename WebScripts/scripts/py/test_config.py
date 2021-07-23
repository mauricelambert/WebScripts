from sys import argv, stdin
from time import sleep

print("Arguments:", " ".join(argv))
inputs = stdin.read()
print("Inputs:", inputs)
print("Inputs end.")
print()

if "-t" in argv or "--timeout" in argv:
    sleep(10)
    print("After timeout error...")

print("end.")
