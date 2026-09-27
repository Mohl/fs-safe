"""Both arms use the exact native bytes built from their unchanged Rust inputs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

if not __debug__:
    raise RuntimeError('qualification requires Python assertion checks')
workspace, work = map(Path, sys.argv[1:])
roots = {role: workspace / role for role in ('A', 'B')}
hashes = {}
for role, root in roots.items():
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', 'native', 'archive-core', 'archive-wasm', 'Cargo.toml', 'Cargo.lock', 'package.json', 'pnpm-lock.yaml', 'packages'], text=True, timeout=30).split('\0')
    hashes[role] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names if name}
assert hashes['A'] == hashes['B'], 'native and dependency sources must be identical'
label = 'win32-x64-msvc' if os.name == 'nt' else 'linux-x64-gnu'
relative = Path('native') / f'fs-safe-native.{label}.node'
source, target = roots['A'] / relative, roots['B'] / relative
assert source.is_file() and not target.exists()
shutil.copyfile(source, target)
digest = hashlib.sha256(source.read_bytes()).hexdigest()
assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
receipt = {'sourceRole': 'A', 'sameVersionAndNativeInputs': True, 'sha256': digest, 'relative': str(relative), 'inputs': hashes['A']}
(work / 'evidence/native-build.json').write_text(json.dumps(receipt, indent=2) + '\n')
