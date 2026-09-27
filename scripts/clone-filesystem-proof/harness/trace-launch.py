"""Bound the raw trace file while inheriting the reviewed step's process group."""
import os
from pathlib import Path
import resource
import sys

trace, *command = sys.argv[1:]
assert command and Path(trace).is_absolute() and not Path(trace).exists()
resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
os.execvp('strace', ['strace', '-f', '-ttt', '-yy', '-s512', '-e', 'trace=fstatfs,write', '-o', trace, *command])
