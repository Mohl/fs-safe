"""Small process/log helper adapted from the previously reviewed Crabbox owner."""
import datetime, json, os, signal, subprocess, time
from pathlib import Path

if not __debug__:raise RuntimeError("qualification requires Python assertion checks")


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stop_signal(signum, frame):
    raise InterruptedError(f'received signal {signum}')


def install_signals():
    for sig in [signal.SIGTERM, signal.SIGINT]: signal.signal(sig, stop_signal)


def settle(child, term_seconds=3):
    errors=[]
    if child is None:return errors
    def alive():
        child.poll()
        try:os.killpg(child.pid,0);return True
        except ProcessLookupError:return False
        except PermissionError as error:errors.append('process-group probe: '+repr(error));return False
    if alive():
        if child.poll()==0:errors.append('successful command left descendants')
        for sig in [signal.SIGTERM,signal.SIGKILL]:
            try:os.killpg(child.pid,sig)
            except ProcessLookupError:break
            except OSError as error:errors.append(repr(error));break
            until=time.monotonic()+(term_seconds if sig==signal.SIGTERM else 3)
            while alive() and time.monotonic()<until:time.sleep(0.05)
            if not alive():break
    try:child.wait(timeout=1)
    except BaseException as error:errors.append(repr(error))
    if alive():errors.append('process group did not settle')
    return errors


def run(directory, label, argv, cap, *, cwd=None, env=None, required=True, settle_seconds=3):
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    assert cap > 0
    save(directory / f'{label}.request.json', {'argv': argv, 'cwd': str(cwd) if cwd else None, 'capSeconds': cap, 'startedAt': now()})
    child = None; failure = None; cleanup_errors = []; start = time.monotonic()
    print(json.dumps({'phase': label, 'startedAt': now(), 'capSeconds': cap}), flush=True)
    with (directory / f'{label}.stdout.log').open('xb') as stdout, (directory / f'{label}.stderr.log').open('xb') as stderr:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            child.wait(timeout=cap)
        except BaseException as error:
            failure = error
        finally:
            cleanup_errors.extend(settle(child, term_seconds=settle_seconds))
            receipt = {'exitCode': None if child is None else child.poll(), 'failure': None if failure is None else repr(failure),
                       'cleanupErrors': cleanup_errors, 'localProcessSettled': child is None or child.poll() is not None,
                       'elapsedSeconds': time.monotonic()-start, 'completedAt': now()}
            save(directory / f'{label}.exit.json', receipt)
    print(json.dumps({'phase': label, **receipt}), flush=True)
    if failure is not None: raise failure
    if cleanup_errors: raise RuntimeError(f'{label}: {cleanup_errors}')
    if required and receipt['exitCode'] != 0: raise RuntimeError(f'{label} exited {receipt["exitCode"]}')
    return receipt
