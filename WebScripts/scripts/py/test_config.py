from functools import partial
from sys import argv, stdin
from time import sleep

print = partial(print, flush=True)

print("Arguments:", " ".join(argv))
inputs = stdin.read()
print("Inputs:")
print(inputs)
print("Inputs end.")

sleep(5)
print("5 seconds...")
sleep(5)
print("10 seconds...")
sleep(5)
print("15 seconds...")

if "-t" in argv or "--timeout" in argv:
    print("TimeoutError is comming... (please wait)...")
    sleep(20)
    print("After timeout error...")

print("end.")
