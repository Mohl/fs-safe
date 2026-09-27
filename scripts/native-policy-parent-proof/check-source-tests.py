"""Verify common test equality and mandatory native-platform rows before timing."""
import json
import os
from pathlib import Path
import re
import sys

if not __debug__:
    raise RuntimeError('qualification requires Python assertion checks')
work = Path(sys.argv[1])
evidence = work / 'evidence'
configuration = json.loads((Path(__file__).parent / 'qualification.json').read_text())


def read(name):
    report = json.loads((evidence / name).read_text(encoding='utf-8'))
    assert report['success'] is True
    rows = []
    for file in report['testResults']:
        for case in file['assertionResults']:
            rows.append((Path(file['name']).name, case['fullName'], case['status']))
    assert rows
    return sorted(rows)


baseline, candidate = read('source-A.json'), read('source-B.json')
assert baseline == candidate, 'common test contracts differ between baseline and candidate'
owner = read('source-owner-B.json')
assert len(owner) == 10 and all(row[2] == 'passed' for row in owner)
adjacent = configuration['windowsAdjacent' if os.name == 'nt' else 'linuxAdjacent']
for case in adjacent:
    matched = [row for row in candidate if row[0] == Path(case['file']).name and re.search(case['pattern'], row[1])]
    assert len(matched) == case['requiredPasses'] and all(row[2] == 'passed' for row in matched), case
if os.name == 'nt':
    native = [row for row in candidate if row[1].startswith('bundled Windows native ')]
    assert len(native) == 8 and all(row[2] == 'passed' for row in native)
else:
    for name in ('pinned-mutation-receipt-walk.test.ts', 'native-policy-directory-observation.test.ts'):
        native = [row for row in candidate if row[0] == name]
        assert native and all(row[2] == 'passed' for row in native), name
result = {'commonContractsEqual': True, 'commonCases': len(candidate), 'candidateOwnerPasses': 10, 'nativeRowsRequired': True}
(evidence / 'source-test-summary.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
