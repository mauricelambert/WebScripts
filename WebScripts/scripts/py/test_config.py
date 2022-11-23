from sys import argv, stdin, stderr, exit
from functools import partial
from time import sleep
from os import environ

# print("Only error...", file=stderr)
# exit(1)

print = partial(print, flush=True)

print("Arguments:", " ".join(argv))
inputs = stdin.read()
print("Inputs:")
print(inputs)
print("Inputs end.")

print(f"Log path: {environ['WEBSCRIPTS_LOGS_PATH']}")

sleep(5)
print("5 seconds...")
sleep(5)
print("10 seconds...")
sleep(5)
print("15 seconds...")
stderr.write("My custom error (15 seconds)...")
stderr.flush()

if "-t" in argv or "--timeout" in argv:
    print("TimeoutError is comming... (please wait)...")
    sleep(20)
    print("After timeout error...")

print("end.")
