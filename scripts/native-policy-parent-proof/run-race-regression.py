"""Own the exact B regression-test overlay in A; the caller owns test processes."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


PACKET = Path(__file__).resolve().parent
CONTRACT = json.loads((PACKET / 'race-regression-contract.json').read_text())
RELATIVE = CONTRACT['test']['path']
EXPECTED_HASH = CONTRACT['test']['sha256']


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def git(source, *args):
    # These synchronous metadata children inherit the caller's bounded group.
    return subprocess.check_output(['git', '-C', str(source), *args])


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino}


def directory_identity(directory):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode), f'not a real directory: {directory}')
    return identity(info)


def source_receipt(source, role):
    require(Path(git(source, 'rev-parse', '--show-toplevel').decode().strip()).resolve() == source,
            f'{role}: source must be the worktree root')
    for expression, expected in (('HEAD', CONTRACT['sourcePins'][role]['commit']),
                                 ('HEAD^{tree}', CONTRACT['sourcePins'][role]['tree'])):
        require(git(source, 'rev-parse', expression).decode().strip() == expected,
                f'{role}: source pin mismatch: {expression}')
    return {'path': str(source), **CONTRACT['sourcePins'][role],
            'rootIdentity': directory_identity(source),
            'testDirectoryIdentity': directory_identity(source / 'test')}


def check_status(source, role, overlay=False):
    expected = ('?? ' + RELATIVE + '\0').encode() if overlay else b''
    actual = git(source, 'status', '--porcelain=v1', '-z', '--untracked-files=all',
                 '--ignore-submodules=none')
    require(actual == expected, f'{role}: unexpected tracked/index/untracked changes')


def test_bytes(source):
    target = source / RELATIVE
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                'test must be a regular, single-link file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            content = stream.read()
        after = os.fstat(descriptor)
        require(identity(before) == identity(after) == identity(target.lstat()),
                'test identity changed during read')
        require(hashlib.sha256(content).hexdigest() == EXPECTED_HASH,
                'test bytes differ from the frozen regression')
        require(len(content) == CONTRACT['test']['bytes'], 'test byte count differs')
        return content, identity(after)
    finally:
        os.close(descriptor)


def check_candidate(source):
    content, info = test_bytes(source)
    expected = git(source, 'show', CONTRACT['sourcePins']['B']['commit'] + ':' + RELATIVE)
    require(content == expected, 'candidate test differs from its pinned Git blob')
    return content, info


def prepare(sources, evidence, attempt):
    evidence.mkdir(mode=0o700)
    save(evidence / 'attempt.json', {'attemptToken': attempt,
                                     'evidenceIdentity': directory_identity(evidence)})
    receipts = {role: source_receipt(source, role) for role, source in sources.items()}
    for role, source in sources.items():
        check_status(source, role)
    require(not git(sources['A'], 'ls-files', '--', RELATIVE), 'baseline already tracks test')
    candidate_bytes, candidate_identity = check_candidate(sources['B'])
    target = sources['A'] / RELATIVE
    require(not os.path.lexists(target), 'baseline test path already exists')
    intent = {'schema': 1, 'attemptToken': attempt, 'sources': receipts, 'test': CONTRACT['test'],
              'candidateTestIdentity': candidate_identity,
              'baselineException': 'one untracked test overlay; no tracked source edits'}
    save(evidence / 'intent.json', intent)
    parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(identity(os.fstat(parent_fd)) == receipts['A']['testDirectoryIdentity'],
                'baseline test directory changed')
        descriptor = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent_fd)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'invalid new overlay')
            save(evidence / 'ownership.json', {'attemptToken': attempt, 'identity': identity(info),
                                               'sha256': EXPECTED_HASH})
            remaining = memoryview(candidate_bytes)
            while remaining:
                written = os.write(descriptor, remaining)
                require(written > 0, 'short overlay write')
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    _, copied_identity = test_bytes(sources['A'])
    require(copied_identity == json.loads((evidence / 'ownership.json').read_text())['identity'],
            'overlay identity changed')
    for role, source in sources.items():
        require(source_receipt(source, role) == receipts[role], f'{role}: source identity changed')
        check_status(source, role, overlay=role == 'A')
    save(evidence / 'prepared.json', {'state': 'complete', 'attemptToken': attempt, 'sources': receipts,
                                     'testSha256': EXPECTED_HASH, 'overlayIdentity': copied_identity})


def cleanup(sources, evidence, attempt):
    require(json.loads((evidence / 'attempt.json').read_text()) == {
        'attemptToken': attempt, 'evidenceIdentity': directory_identity(evidence)},
        'cleanup may not adopt or write into another attempt evidence directory')
    result = {'state': 'incomplete', 'attemptToken': attempt, 'overlayRemoved': False,
              'testSha256': EXPECTED_HASH}
    try:
        receipts = {role: source_receipt(source, role) for role, source in sources.items()}
        target = sources['A'] / RELATIVE
        intent_path = evidence / 'intent.json'
        if intent_path.exists():
            intent = json.loads(intent_path.read_text())
            require(intent['attemptToken'] == attempt, 'cleanup may not adopt another attempt')
            require(intent['sources'] == receipts and intent['test'] == CONTRACT['test'],
                    'cleanup source/contract differs from recorded intent')
        if os.path.lexists(target):
            require(intent_path.is_file(), 'overlay exists without recorded intent; preserving it')
            ownership = json.loads((evidence / 'ownership.json').read_text())
            _, actual_identity = test_bytes(sources['A'])
            require(ownership == {'attemptToken': attempt, 'identity': actual_identity,
                                  'sha256': EXPECTED_HASH},
                    'overlay ownership changed; preserving it')
            require(not git(sources['A'], 'ls-files', '--', RELATIVE), 'overlay became tracked')
            parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(identity(os.fstat(parent_fd)) == receipts['A']['testDirectoryIdentity'],
                        'baseline test directory changed')
                named = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                        and identity(named) == actual_identity, 'overlay replaced before unlink')
                os.unlink(target.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
                result['overlayRemoved'] = True
            finally:
                os.close(parent_fd)
        check_candidate(sources['B'])
        for role, source in sources.items():
            require(source_receipt(source, role) == receipts[role], f'{role}: source identity changed')
            check_status(source, role)
        require(not os.path.lexists(target), 'baseline overlay remains')
        result.update(state='complete', overlayAbsent=True, cleanSources=True, sources=receipts)
    except BaseException as error:
        result['failure'] = repr(error)
        raise
    finally:
        save(evidence / 'cleanup.json', result)


def main():
    require(sys.platform == 'linux', 'race qualification is Linux-only')
    require(len(sys.argv) == 6 and sys.argv[1] in ('prepare', 'cleanup'),
            'usage: run-race-regression.py prepare|cleanup A_SOURCE B_SOURCE EVIDENCE_DIR ATTEMPT_TOKEN')
    action, baseline, candidate, output, attempt = sys.argv[1:]
    require(len(attempt) == 32 and all(char in '0123456789abcdef' for char in attempt),
            'parent must pass a fresh UUID hex attempt token')
    sources = {'A': Path(baseline).resolve(strict=True), 'B': Path(candidate).resolve(strict=True)}
    evidence = Path(output).resolve()
    require(sources['A'] != sources['B'], 'A and B must be separate worktrees')
    for source in sources.values():
        require(evidence != source and source not in evidence.parents,
                'overlay evidence must be outside both source worktrees')
    if action == 'prepare':
        prepare(sources, evidence, attempt)
    else:
        require(evidence.is_dir() and not evidence.is_symlink(), 'missing real evidence directory')
        cleanup(sources, evidence, attempt)


if __name__ == '__main__':
    main()
