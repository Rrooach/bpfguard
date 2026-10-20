#!/usr/bin/env python3
"""Exec gate: wrapper has exec'd, then stops before any selected workload."""
import os
import signal
import sys

os.kill(os.getpid(), signal.SIGSTOP)
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
