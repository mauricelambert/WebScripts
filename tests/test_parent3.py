# python3 test_parent3.py

# https://www.stefaanlippens.net/python-asynchronous-subprocess-pipe-reading/
# https://living-sun.com/fr/python/690674-man-in-the-middle-attack-with-scapy-python-network-programming-exploit-scapy-man-in-the-middle.html

############
#   VII
############

from subprocess import Popen, PIPE
from threading import Thread
from time import time
import sys


def write1():  # pass !
    process.stdin.flush()
    process.stdin.write(b"abc\n")
    process.stdin.flush()
    process.stdin.write(b"def\n")
    process.stdin.flush()
    process.stdin.write(b"ghi\n")
    process.stdin.flush()
    process.stdin.write(b"jkl\n")
    process.stdin.flush()
    process.stdin.close()


def print_stdout():
    process.stdout.flush()
    print(data := process.stdout.readline())
    while data:
        print(data := process.stdout.readline())
        process.stdout.flush()


start = time()
process = Popen(
    ["python", "test_enfant3.py"], stdin=PIPE, stdout=PIPE, stderr=PIPE
)
print("pass1")
write1()
print(time() - start)
print("pass3")
t = Thread(target=print_stdout)
t.start()
t.join()
print(time() - start)
print("pass5")

exit(0)  # Works but wait the end of the process

############
#   VII
############

import sys
import subprocess
import random
import time
import threading
import queue


class AsynchronousFileReader(threading.Thread):
    """
    Helper class to implement asynchronous reading of a file
    in a separate thread. Pushes read lines on a queue to
    be consumed in another thread.
    """

    def __init__(self, fd, queue_):
        assert isinstance(queue_, queue.Queue)
        assert callable(fd.readline)
        threading.Thread.__init__(self)
        self._fd = fd
        self._queue = queue_

    def run(self):
        """The body of the tread: read lines and put them on the queue."""
        for line in iter(self._fd.readline, None):
            if not line:
                break
            self._queue.put(line)

    def eof(self):
        """Check whether there is no more content to expect."""
        print(not self.is_alive())
        print(self._queue.empty())
        return not self.is_alive() and self._queue.empty()


def consume(command):
    """
    Example of how to consume standard output and standard error of
    a subprocess asynchronously without risk on deadlocking.
    """

    # Launch the command as subprocess.
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Launch the asynchronous readers of the process' stdout and stderr.
    stdout_queue = queue.Queue()
    stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
    stdout_reader.start()
    stderr_queue = queue.Queue()
    stderr_reader = AsynchronousFileReader(process.stderr, stderr_queue)
    stderr_reader.start()

    # Check the queues if we received some output (until there is nothing more to get).
    while not stdout_reader.eof() or not stderr_reader.eof():
        # Show what we received from standard output.
        while not stdout_queue.empty():
            print("stdout", not stdout_queue.empty())
            line = stdout_queue.get()
            print("Received line on standard output: " + repr(line))
            stdout_queue.task_done()

        # Show what we received from standard error.
        while not stderr_queue.empty():
            print("stderr", not stdout_queue.empty())
            line = stderr_queue.get()
            print("Received line on standard error: " + repr(line))
            stderr_queue.task_done()

        # Sleep a bit before asking the readers again.
        time.sleep(0.1)

    # Let's be tidy and join the threads we've started.
    stdout_reader.join()
    stderr_reader.join()

    # Close subprocess' file descriptors.
    process.stdout.close()
    process.stderr.close()


def produce(items=10):
    """
    Dummy function to randomly render a couple of lines
    on standard output and standard error.
    """
    for i in range(items):
        output = random.choice([sys.stdout, sys.stderr])
        output.write("Line %d on %s\n" % (i, output))
        output.flush()
        time.sleep(random.uniform(0.1, 1))


if __name__ == "__main__":
    # The main flow:
    # if there is an command line argument 'produce', act as a producer
    # otherwise be a consumer (which launches a producer as subprocess).
    if len(sys.argv) == 2 and sys.argv[1] == "produce":
        produce(10)
    else:
        consume(["python", sys.argv[0], "produce"])

exit(0)

############
#    VI
############

from subprocess import PIPE
from asyncio import *
from time import time


async def get_lines():
    start = time()
    process = await create_subprocess_exec(
        "python3", "test_enfant3.py", stdout=PIPE
    )
    line = await process.stdout.readline()
    while line and process.returncode is None:
        print(line, time() - start)
        line = await process.stdout.readline()


run(get_lines())
exit(0)

############
#    V
############

import subprocess
import sys
import os
import select


def run_script(cmd, rtoutput=0):
    p = subprocess.Popen(
        cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    poller = select.poll()  # Linux only
    poller.register(p.stdout, select.POLLIN)
    poller.register(p.stderr, select.POLLIN)

    coutput = ""
    cerror = ""
    fdhup = {}
    fdhup[p.stdout.fileno()] = 0
    fdhup[p.stderr.fileno()] = 0

    while sum(fdhup.values()) < len(fdhup):
        try:
            r = poller.poll(1)
        except (select.error, err):
            if err.args[0] != EINTR:
                raise
            r = []

        for fd, flags in r:
            if flags & (select.POLLIN | select.POLLPRI):
                c = os.read(fd, 1024)
                if rtoutput:
                    sys.stdout.write(c)
                    sys.stdout.flush()
                if fd == p.stderr.fileno():
                    cerror += c
                else:
                    coutput += c
            else:
                fdhup[fd] = 1

    return p.poll(), coutput.strip(), cerror.strip()


run_script(["python", "test_enfant3.py"])
exit(0)

############
#   IV
############

from time import time
import subprocess
import sys

start = time()
with open("test.log", "wb") as f:
    process = subprocess.Popen(
        ["python", "test_enfant3.py"], stdout=subprocess.PIPE
    )
    for c in iter(lambda: process.stdout.read(1), b""):
        print(c, time() - start)
        f.write(c)

exit(0)


################
#   III
################

from subprocess import Popen, PIPE
from time import time
import sys


def write1():  # pass !
    process.stdin.flush()
    process.stdin.write(b"abc\n")
    process.stdin.flush()
    process.stdin.write(b"def\n")
    process.stdin.flush()
    process.stdin.write(b"ghi\n")
    process.stdin.flush()
    process.stdin.write(b"jkl\n")
    process.stdin.flush()
    process.stdin.close()


def write2():  # block !
    process.stdin.flush()
    process.stdin.write(b"abc\ndef\nghi\njkl\n")
    process.stdin.flush()
    process.stdin.close()


start = time()
process = Popen(
    ["python", "test_enfant3.py"], stdin=PIPE, stdout=PIPE, stderr=PIPE
)
print("pass1")
write1()
# write2()
print("pass2")

# for line in process.stdout:
#     if not line and process.poll() is not None:
#         break
#     print(line, time() - start)

# exit(0)                    # Works but wait the end of the process
process.stdout.flush()
print(data := process.stdout.readline())
process.stdout.flush()
print(data := process.stdout.readline())
process.stdout.flush()
print(time() - start)
print("pass3")
print(process.stdout.tell())
print(process.stdout.seek(0))
process.stdout.flush()
print(data := process.stdout.readline())  # pass !
process.stdout.flush()
print(data := process.stdout.readline())  # pass !
process.stdout.flush()
print("pass4")

while data:
    print(data := process.stdout.readline())  # pass !
    process.stdout.flush()

print(time() - start)
print("pass5")

exit(0)  # Works but wait the end of the process

####################
#       I
####################

# http://eyalarubas.com/python-subproc-nonblock.html

from threading import Thread
from queue import Queue, Empty


class NonBlockingStreamReader:
    def __init__(self, stream):
        """
        stream: the stream to read from.
                Usually a process' stdout or stderr.
        """

        self._s = stream
        self._q = Queue()

        def _populateQueue(stream, queue):
            """
            Collect lines from 'stream' and put them in 'quque'.
            """

            while True:
                line = stream.readline()
                if line:
                    queue.put(line)
                else:
                    raise UnexpectedEndOfStream

        self._t = Thread(target=_populateQueue, args=(self._s, self._q))
        self._t.daemon = True
        self._t.start()  # start collecting lines from the stream

    def readline(self, timeout=None):
        try:
            return self._q.get(block=timeout is not None, timeout=timeout)
        except Empty:
            return None


class UnexpectedEndOfStream(Exception):
    pass


process = Popen(
    ["python", "test_enfant3.py"], stdin=PIPE, stdout=PIPE, stderr=PIPE
)
nsbr = NonBlockingStreamReader(process.stdout)

print("pass1")
process.stdin.write(b"abc\ndef\nghi\njkl\n")
print("pass2")
print(data := nsbr.readline())
print(data := nsbr.readline())
print("pass3")
print(process.stdout.tell())
print(process.stdout.seek(0))
print(data := nsbr.readline())  # block !
print("pass4")

exit(0)

################
#   II
################

with open("a.txt", "wb") as a:
    process = Popen(
        ["python", "test_enfant3.py"], stdin=PIPE, stdout=a, stderr=PIPE
    )
    print("pass1")
    process.stdin.write(b"abc\ndef\nghi\njkl\n")
    print("pass2")
    process.communicate()

with open("a.txt") as a:
    print(a.read())

exit(0)
