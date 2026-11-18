"""Own the restricted proxy's lifetime from inside its user namespace."""

import signal
import subprocess
import sys


def main():
    executable, profile, *command = sys.argv[1:]
    child = None
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True
        if child is not None:
            child.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if stopping:
        return 0
    child = subprocess.Popen(command, pass_fds=(int(executable), int(profile)))
    if stopping:
        child.terminate()
    try:
        while not stopping:
            try:
                return child.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                pass
        return child.wait(timeout=0.75)
    except subprocess.TimeoutExpired:
        child.kill()
        return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
