"""Require the pinned Linux source cases to execute equally in both native arms."""
import json
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError('qualification requires assertions')
packet = Path(__file__).resolve().parent
pins = json.loads((packet / 'pins.json').read_text())
protocol = json.loads((packet / 'protocol.json').read_text())
assert pins['ready'] is True and protocol['ready'] is True
work = Path(sys.argv[1]).resolve(); evidence = work / 'evidence'
config = json.loads((packet / 'qualification.json').read_text())
expected_files = {Path(name).name for name in config['sourceTests']}


def read(name, files):
    report = json.loads((evidence / name).read_text())
    assert report['success'] is True
    rows = []
    observed = set()
    for file in report['testResults']:
        basename = Path(file['name']).name; observed.add(basename)
        assert file['assertionResults'], basename
        for case in file['assertionResults']:
            assert case['status'] == 'passed', (basename, case['fullName'], case['status'])
            rows.append((basename, case['fullName'], case['status']))
    assert observed == files and rows
    assert len(rows) == len(set(rows)), 'duplicate source case receipt'
    return sorted(rows)


result = {'state': 'complete', 'mechanisms': {}, 'allSelectedRowsExecuted': True}
for mechanism in config['sourceMechanisms']:
    baseline = read(f'source-A-{mechanism}.json', expected_files)
    candidate = read(f'source-B-{mechanism}.json', expected_files)
    assert baseline == candidate, mechanism
    result['mechanisms'][mechanism] = {'casesPerArm': len(candidate), 'commonContractsEqual': True}
left = read('seccomp-parity-A.json', {'linux-openat2-parity.test.ts'})
right = read('seccomp-parity-B.json', {'linux-openat2-parity.test.ts'})
assert left == right
result['seccompParity'] = {'casesPerArm': len(left), 'mechanism': 'ENOSYS', 'commonContractsEqual': True}
(evidence / 'source-test-summary.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
