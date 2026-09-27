"""One bounded step; Node awaits this owner's exit and settlement receipt."""
import os
import sys
import bounded
from settlement_control import install

directory, label, cap, *argv = sys.argv[1:]
assert label and "/" not in label and ".." not in label
assert argv and float(cap) > 0
install()
bounded.run(directory, label, argv, float(cap), cwd=os.getcwd(), env=os.environ.copy())
