"""Arrange for the managed process to stop if its owner exits."""

import ctypes
import os
import signal
import sys

parent, *command = sys.argv[1:]
prctl = ctypes.CDLL(None, use_errno=True).prctl
if prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != int(parent):
    sys.exit("VPN Dock stopped before its child process started.")
os.execv(command[0], command)
