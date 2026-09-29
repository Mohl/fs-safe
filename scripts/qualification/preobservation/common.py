"""Evidence helpers for the one-shot, source-pinned qualification carrier."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
PACKET_HASHES = {
    'measure.mjs': '8963c048806c5c3b0aa4b8c5e2ccaef207776941b335dbb01f3198e6c027c0ba',
    'campaign.py': 'ee73d7c1b21fdf5f3d391feea3a3d187fbe82a7a4405019ce0f3b93787787b16',
    'PROTOCOL.md': '6635e1dea370ef8b55f588d129aed20b7878349409bbc51e017ec1b401ce3f54',
}
SOURCES = {
    'A': ('baseline', '9543f52cc075385e149c130c32927a25e77dc4f6'),
    'B': ('candidate', 'd27b43ac9373869af42548b6f296d9bd9b130936'),
}
PHASE_DEADLINE = None


def private_layout():
    root = Path(os.environ['FS_SAFE_PROOF_ROOT']).resolve()
    require(root == Path(os.environ['GITHUB_WORKSPACE']).resolve() / 'fs-safe-preobservation.noindex', 'private root changed')
    paths = {name: root / relative for name, relative in {
        'root': '.', 'harness': 'harness', 'baseline': 'baseline', 'candidate': 'candidate',
        'evidence': 'evidence', 'tooling': 'tooling', 'cargo': 'tooling/cargo', 'rustup': 'tooling/rustup',
        'pnpm': 'tooling/pnpm', 'cache': 'caches', 'pnpmStore': 'caches/pnpm', 'npmCache': 'caches/npm',
        'clangCache': 'caches/clang', 'targetA': 'target-A', 'targetB': 'target-B',
        'consumerA': 'consumer-A', 'consumerB': 'consumer-B', 'tmp': 'tmp',
    }.items()}
    for name, path in paths.items():
        require(path.resolve().is_relative_to(root), 'private path escaped: ' + name)
    for name, key in {'EVIDENCE_ROOT': 'evidence', 'TMPDIR': 'tmp', 'CARGO_HOME': 'cargo', 'RUSTUP_HOME': 'rustup',
                      'PNPM_HOME': 'pnpm', 'npm_config_cache': 'npmCache', 'XDG_CACHE_HOME': 'cache',
                      'CLANG_MODULE_CACHE_PATH': 'clangCache'}.items():
        require(Path(os.environ[name]).resolve() == paths[key].resolve(), name + ' changed')
    require(os.environ.get('HOME') == read(root / 'lifecycle.json')['originalHome'], 'HOME changed')
    return paths


def task_deadline():
    if 'FS_SAFE_PROOF_ROOT' not in os.environ:
        return None
    lifecycle = read(Path(os.environ['FS_SAFE_PROOF_ROOT']) / 'lifecycle.json')
    require(lifecycle['taskWorkSeconds'] == 6600, 'task-work budget changed')
    return lifecycle['startedMonotonic'] + lifecycle['taskWorkSeconds']


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def terminate_group(pid):
    if group_exists(pid):
        os.killpg(pid, signal.SIGKILL)
    # Cleanup is bounded; it never admits another timing attempt.
    deadline = time.monotonic() + 5
    while group_exists(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not group_exists(pid)


def reserve_budget(deadline, seconds):
    if deadline is not None:
        require(time.monotonic() + seconds + 10 <= deadline,
                'overall resource budget cannot reserve the full command timeout and cleanup; incomplete, no retry')


def run(directory, name, command, *, cwd=None, extra_env=None, timeout=600, deadline=None):
    """Retain invocation/output; terminate the process group on any failure."""
    deadlines = [value for value in [deadline, PHASE_DEADLINE, task_deadline()] if value is not None]
    deadline = min(deadlines) if deadlines else None
    reserve_budget(deadline, timeout)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    command = [str(item) for item in command]
    write(directory / f'{name}.command.json', dict(argv=command, cwd=str(cwd) if cwd else None,
          environmentOverrides=extra_env or {}, timeoutSeconds=timeout))
    env = dict(os.environ, **(extra_env or {}))
    print(f'{name}: start', flush=True)
    started = time.monotonic()
    with (directory / f'{name}.stdout').open('xb') as out, (directory / f'{name}.stderr').open('xb') as err:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        timed_out = False
        interrupted = None
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        except BaseException as error:
            interrupted = type(error).__name__
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        finally:
            lingering = group_exists(child.pid)
            group_gone = terminate_group(child.pid)
    terminal = dict(pid=child.pid, returncode=child.returncode, timedOut=timed_out,
                    interrupted=interrupted, lingeringProcessGroup=lingering,
                    processGroupGone=group_gone, elapsedSeconds=time.monotonic() - started)
    write(directory / f'{name}.terminal.json', terminal)
    print(f'{name}: exit {child.returncode}', flush=True)
    require(not timed_out and not lingering and not interrupted and group_gone and child.returncode == 0, f'{name} failed: {terminal}')
    return (directory / f'{name}.stdout').read_text()


def pin_files(directory):
    return {str(path.relative_to(directory)): digest(path)
            for path in sorted(Path(directory).rglob('*')) if path.is_file()}


def verify_packet():
    for name, expected in PACKET_HASHES.items():
        require(digest(HERE / 'frozen' / name) == expected, f'frozen {name} changed')
    require(digest(HERE / 'installed-probe.mjs') ==
            '4dc8ed95985443f2c4ea68f4b8ef08bdb9e9fee4d7ce04fc3f94ce3418e0c027', 'installed probe changed')
    require(digest(HERE / 'PROTOCOL.md') ==
            '14cd348dc1757676dc32bbbe98d70bd681be7ce0ad47dacab39e2e3874fd4aa4', 'larger-VM protocol changed')
