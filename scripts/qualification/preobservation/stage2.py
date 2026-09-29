#!/usr/bin/env python3
"""Observe the frozen driver's subprocess calls without changing their launch."""
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, require, verify_packet, write


def observed_run(original_run, *args, **kwargs):
    require(len(args) == 1 and len(args[0]) == 4, 'unexpected frozen subprocess invocation')
    require(set(kwargs) == {'cwd', 'env', 'stdout', 'stderr', 'timeout', 'check'}, 'unexpected process launch options')
    require(args[0][1] == str(HERE / 'frozen/measure.mjs') and kwargs['timeout'] == 600 and kwargs['check'] is False,
            'frozen measurement invocation changed')
    report = Path(args[0][3])
    group = os.getpgrp()
    ownership = dict(driverPid=os.getpid(), driverProcessGroupId=group, expectedInheritedProcessGroupId=group,
                     cleanupReceipt='../qualification.terminal.json')
    write(report.with_suffix('.command.json'), dict(argv=args[0], cwd=kwargs['cwd'],
          stdout=str(kwargs['stdout'].name), stderr=str(kwargs['stderr'].name), timeoutSeconds=kwargs['timeout'],
          environment='forwarded unchanged from frozen campaign.py', processFlags='unchanged; inherit driver process group',
          **ownership))
    started = time.monotonic()
    terminal = dict(returncode=None, timedOut=False, error=None, **ownership)
    try:
        result = original_run(*args, **kwargs)
        terminal['returncode'] = result.returncode
        return result
    except BaseException as error:
        terminal['timedOut'] = isinstance(error, subprocess.TimeoutExpired)
        terminal['error'] = type(error).__name__
        raise
    finally:
        terminal['elapsedSeconds'] = time.monotonic() - started
        write(report.with_suffix('.terminal.json'), terminal)


def main():
    require(len(sys.argv) == 4 and sys.argv[1] == 'run', 'usage: stage2.py run CONFIG NEW_DIR')
    require(os.getpid() == os.getpgrp(), 'outer carrier must own the campaign process group')
    verify_packet()
    original_run = subprocess.run
    original_argv = sys.argv
    try:
        subprocess.run = lambda *args, **kwargs: observed_run(original_run, *args, **kwargs)
        sys.argv = [str(HERE / 'frozen/campaign.py'), *original_argv[1:]]
        runpy.run_path(sys.argv[0], run_name='__main__')
    finally:
        subprocess.run = original_run
        sys.argv = original_argv


if __name__ == '__main__':
    main()
