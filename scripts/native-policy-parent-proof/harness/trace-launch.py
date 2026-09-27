"""Run one untimed trace inside the existing bounded owner's process group."""
import os
from pathlib import Path
import resource
import sys

trace, *command = sys.argv[1:]
assert command and Path(trace).is_absolute() and not Path(trace).exists()
resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
# Full stat structures are required for within-arm identity checks. Explicitly
# re-abbreviate exec environment vectors after -v so inherited values stay out.
os.execvp('strace', ['strace', '-f', '-ttt', '-yy', '-s1024', '-v', '-e', 'abbrev=execve,execveat',
    '-e', 'trace=%file,fstat,close,write,fchmod,fsync,fdatasync,dup,dup2,dup3,fcntl', '-o', trace, *command])
