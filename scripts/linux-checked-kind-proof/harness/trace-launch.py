"""Capture one untimed call; all processes stay in the existing bounded group."""
import hashlib
import os
from pathlib import Path
import resource
import runpy
import stat
import subprocess
import sys

packet = Path(__file__).resolve().parent.parent
helpers = runpy.run_path(str(packet / 'harness/compare-syscalls.py'))
require, read_input, json_value = (helpers[key] for key in ('require', 'read_input', 'json_value'))
snapshot = helpers['snapshot']
provenance = {}


def read_json(path):
    receipt = {}
    raw = read_input(path, 128 * 1024, receipt)
    provenance[str(path)] = receipt
    return json_value(raw), raw


def digest_file(path):
    path = Path(path).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024 * 1024, 'artifact is not a bounded regular file')
        digest, length = hashlib.sha256(), 0
        while chunk := os.read(fd, 1024 * 1024):
            length += len(chunk)
            require(length <= before.st_size, 'artifact grew while hashing')
            digest.update(chunk)
        require(length == before.st_size and snapshot(before) == snapshot(os.fstat(fd)) == snapshot(os.lstat(path)), 'artifact changed while hashing')
        return {'path': str(path), 'sha256': digest.hexdigest()}
    finally:
        os.close(fd)


pins, pins_raw = read_json(packet / 'pins.json')
protocol, protocol_raw = read_json(packet / 'protocol.json')
rows = helpers['verify_protocol'](pins, protocol)
require(os.environ.get('FS_SAFE_TEST_NO_OPENAT2') == '0', 'environment fallback hook must be explicitly disabled')
require(len(sys.argv) >= 3, 'trace requires a new absolute output and command')
trace, *command = sys.argv[1:]
trace_path = Path(helpers['canonical'](trace))
script_positions = [index for index, value in enumerate(command) if value.endswith('/harness/syscall-probe.mjs')]
require(len(script_positions) == 1 and script_positions[0] in (1, 3), 'unexpected trace probe command')
node_index = script_positions[0] - 1
require(len(command) == node_index + 8, 'unexpected probe argument count')
row, major = command[node_index + 4:node_index + 6]
require(row in rows and major in protocol['nodeVersions'], 'unknown trace row or Node version')
mechanism = rows[row]['mechanism']
require(node_index == (0 if mechanism == 'openat2' else 2), 'trace mechanism command shape differs')
for index in (node_index, node_index + 1, node_index + 2, node_index + 3, node_index + 6, node_index + 7):
    helpers['canonical'](command[index])
runtime = digest_file(command[node_index])
require(Path(runtime['path']).name == 'node', 'trace runtime is not Node')
wrapper = None
if node_index:
    receipt_path = os.environ.get('FS_SAFE_PROOF_DENY_BUILD_RECEIPT')
    require(receipt_path, 'denial wrapper build receipt not configured')
    receipt, receipt_raw = read_json(receipt_path)
    require(set(receipt) == {'sourcePath', 'sourceSha256', 'binaryPath', 'binarySha256', 'compilerPath', 'compilerSha256', 'command', 'processLabel'}, 'unexpected denial build receipt fields')
    require(receipt['processLabel'] == 'compile-deny-wrapper', 'unexpected denial build owner')
    source, binary, compiler = (digest_file(receipt[key]) for key in ('sourcePath', 'binaryPath', 'compilerPath'))
    require(source['sha256'] == receipt['sourceSha256'] == digest_file(packet / 'harness/deny-openat2.c')['sha256'], 'denial source differs from frozen harness')
    require(binary['sha256'] == receipt['binarySha256'] == os.environ.get('FS_SAFE_PROOF_DENY_WRAPPER_SHA256'), 'denial binary differs from build receipt/environment')
    require(compiler['sha256'] == receipt['compilerSha256'], 'denial compiler differs from build receipt')
    require(command[0] == receipt['binaryPath'] == os.environ.get('FS_SAFE_PROOF_DENY_WRAPPER') and command[1] == mechanism, 'denial wrapper invocation differs from configured compiled wrapper')
    require(receipt['command'] == [receipt['compilerPath'], receipt['sourcePath'], '-o', receipt['binaryPath']], 'denial compile command differs from frozen recipe')
    wrapper = {'buildReceipt': receipt, 'buildReceiptText': receipt_raw.decode('utf-8'),
               'buildReceiptSha256': hashlib.sha256(receipt_raw).hexdigest()}
parent = trace_path.parent
before_parent = os.lstat(parent)
require(stat.S_ISDIR(before_parent.st_mode) and before_parent.st_uid == os.getuid() and before_parent.st_mode & 0o022 == 0,
        'trace parent must be a task-owned directory without group/other write permission')
require(parent.resolve(strict=True) == parent, 'trace parent contains symlinks')
launch = {'schema': 1, 'tracePath': trace, 'command': command, 'runtime': runtime, 'row': row,
          'nodeMajor': int(major), 'mechanism': mechanism, 'fallbackHook': '0', 'denialWrapper': wrapper,
          'pinsSha256': hashlib.sha256(pins_raw).hexdigest(), 'protocolSha256': hashlib.sha256(protocol_raw).hexdigest(),
          'outputOwnership': 'exclusive O_NOFOLLOW descriptor; strace opens /proc/launcher/fd; no inherited product descriptor'}
launch_path = trace_path.with_name(trace_path.name + '.launch.json')
# Reserving the output with an owned fd prevents strace -o from following a
# substituted pathname. The fd stays CLOEXEC; it is never passed to the product.
fd = os.open(trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
child = None
try:
    held = os.fstat(fd)
    require(snapshot(held) == snapshot(os.lstat(trace_path)), 'trace pathname does not identify reserved descriptor')
    helpers['save_output'](launch_path, launch)
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
    # Full stat/filter structures are required; explicitly re-abbreviate exec
    # environments after -v so inherited values do not enter retained evidence.
    child = subprocess.Popen(['strace', '-f', '-ttt', '-yy', '-s1024', '-v', '-e', 'abbrev=execve,execveat',
        '-e', 'trace=%file,fstat,fstatfs,prctl,seccomp,close,write,fchmod,fsync,fdatasync,dup,dup2,dup3,fcntl',
        '-o', f'/proc/{os.getpid()}/fd/{fd}', *command], close_fds=True)
    # Same inherited process group, no detached child/new session/timeout owner.
    # The existing outer bounded owner supplies cancellation and group settlement.
    result = child.wait()
    after = os.fstat(fd)
    require((held.st_dev, held.st_ino) == (after.st_dev, after.st_ino)
            and snapshot(after) == snapshot(os.lstat(trace_path)), 'trace pathname identity changed during capture')
    require(after.st_size <= 32 * 1024 * 1024, 'trace exceeded capture limit')
    require((before_parent.st_dev, before_parent.st_ino) == (os.lstat(parent).st_dev, os.lstat(parent).st_ino), 'trace parent changed during capture')
    sys.exit(result if result >= 0 else 128 - result)
finally:
    if child is not None and child.poll() is not None:
        child.wait()
    os.close(fd)
