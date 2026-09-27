"""Archive only regular, task-owned receipts after every dispatched child settled."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile

if not __debug__:
    raise RuntimeError('qualification requires Python assertion checks')

packet = Path(__file__).resolve().parent
work = Path(sys.argv[1]).resolve()
evidence = work / 'evidence'
processes = evidence / 'processes'
assert processes.is_dir(), 'no process ownership evidence'
requests = sorted(processes.glob('*.request.json'))
assert requests, 'no commands were dispatched'
for request in requests:
    terminal = request.with_name(request.name.replace('.request.json', '.exit.json'))
    receipt = json.loads(terminal.read_text())
    assert receipt['localProcessSettled'] is True, terminal
    assert not receipt['cleanupErrors'], terminal
files = []
for file in sorted(evidence.rglob('*')):
    assert not file.is_symlink(), file
    if file.is_dir():
        continue
    assert file.is_file() and file.stat().st_size <= 32 * 1024 * 1024, file
    files.append((file, str(Path('evidence') / file.relative_to(evidence))))
manifest = json.loads((packet / 'packet-manifest.json').read_text())
for name in [*manifest['files'], 'packet-manifest.json']:
    file = packet / name
    assert file.is_file() and not file.is_symlink()
    if name != 'packet-manifest.json':
        assert hashlib.sha256(file.read_bytes()).hexdigest() == manifest['files'][name]
    files.append((file, str(Path('packet') / name)))
output = work / 'parent-proof.tar.gz'
assert not output.exists()
with tarfile.open(output, 'w:gz') as archive:
    for file, name in files:
        archive.add(file, arcname=name, recursive=False)
receipt = {'archive': output.name, 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'settledRequests': len(requests), 'files': len(files)}
(work / 'archive.json').write_text(json.dumps(receipt, indent=2) + '\n')
if os.environ.get('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('safe=true\n')
print(json.dumps(receipt))
