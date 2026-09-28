"""Synthetic statistical/provenance receipts only; never load or execute fs-safe."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.packet = self.root / 'packet'
        self.legs = self.root / 'legs'; self.evidence = self.root / 'evidence'
        self.protocol = json.loads((SOURCE / 'protocol.json').read_text()); self.protocol['ready'] = True
        self.pins = json.loads((SOURCE / 'pins.json').read_text()); self.pins['ready'] = True
        write(self.packet / 'protocol.json', self.protocol); write(self.packet / 'pins.json', self.pins)
        script = self.packet / 'harness/assess.py'; script.parent.mkdir(); script.write_bytes((SOURCE / 'harness/assess.py').read_bytes())
        spec = importlib.util.spec_from_file_location('synthetic_assess', script)
        self.module = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.module)
        self.expected = {}
        for role, digest in [('A', 'a' * 64), ('B', 'b' * 64)]:
            expected = {'role': role, 'source': {**self.pins[role], 'dirty': False}, 'nativeSha256': digest,
                        'pinsSha256': sha(self.packet / 'pins.json'), 'protocolSha256': sha(self.packet / 'protocol.json')}
            self.expected[role] = expected; write(self.evidence / f'expected-{role}.json', expected)
        for cohort in self.protocol['timing']['cohorts']:
            descriptors = [next(row for row in self.protocol['rows'] if row['id'] == name) for name in cohort['rows']]
            for index, plan in enumerate(self.protocol['timing']['schedule'], 1):
                ordered = list(reversed(descriptors)) if plan['rowOrder'] == 'reverse' else descriptors
                rows = {row['id']: {'descriptor': row, 'warmups': 5, 'checkedUntimed': 1, 'callsPerSample': 10,
                                   'samples': [[100.0] * 10 for _ in range(5)], 'sampleMeansUs': [100.0] * 5} for row in ordered}
                leg = {'state': 'complete', 'cleanup': True, 'platform': 'linux', 'cohort': cohort['id'],
                       'mechanism': cohort['mechanism'], 'nodeVersion': self.protocol['nodeVersions']['24'],
                       'nodeMajor': 24, 'fallbackHook': '0', **plan, 'source': self.expected[plan['role']]['source'],
                       'native': {'configuredMode': 'require', 'nativePackage': self.protocol['nativePackage'],
                                  'sha256': self.expected[plan['role']]['nativeSha256'], 'path': '/synthetic/native.node'}, 'rows': rows}
                write(self.legs / cohort['id'] / f'leg-{index:02d}.json', leg)

    def assess(self):
        output = self.root / 'assessment.json'
        with patch.object(sys, 'argv', ['assess.py', str(self.legs), str(self.evidence), str(output)]):
            result = self.module.main()
        return result, json.loads(output.read_text())

    def change_leg(self, change):
        target = self.legs / 'fallback/leg-02.json'
        data = json.loads(target.read_text()); change(data); write(target, data)

    def test_complete_distinct_native_pair_passes_and_counts_exactly(self):
        code, report = self.assess()
        self.assertEqual(code, 0); self.assertTrue(report['validInput']); self.assertEqual(report['performanceOutcome'], 'pass')
        self.assertEqual((report['completedLegs'], report['sampleMeans'], report['measuredCalls'], report['warmupAndCheckedCalls']), (64, 800, 8000, 960))
        self.assertEqual(len(report['cells']), 5)

    def test_shared_native_artifact_is_rejected(self):
        self.expected['B']['nativeSha256'] = self.expected['A']['nativeSha256']
        write(self.evidence / 'expected-B.json', self.expected['B'])
        code, report = self.assess(); self.assertEqual(code, 1); self.assertFalse(report['validInput'])

    def test_wrong_arm_native_is_rejected(self):
        self.change_leg(lambda leg: leg['native'].update(sha256='c' * 64))
        code, _ = self.assess(); self.assertEqual(code, 1)

    def test_wrong_node_or_hook_is_rejected(self):
        self.change_leg(lambda leg: leg.update(nodeVersion='v24.0.0', fallbackHook='1'))
        code, _ = self.assess(); self.assertEqual(code, 1)

    def test_missing_leg_cannot_shrink_matrix(self):
        (self.legs / 'kernel/leg-32.json').unlink()
        code, _ = self.assess(); self.assertEqual(code, 1)

    def test_forged_mean_is_rejected(self):
        def change(leg):
            next(iter(leg['rows'].values()))['sampleMeansUs'][0] = 1
        self.change_leg(change)
        code, _ = self.assess(); self.assertEqual(code, 1)

    def test_valid_slow_source_is_hold_even_with_passing_controls(self):
        for file in (self.legs / 'fallback').glob('leg-*.json'):
            leg = json.loads(file.read_text())
            if leg['role'] == 'B':
                selected = leg['rows']['enosys-depth8']
                selected['samples'] = [[110.0] * 10 for _ in range(5)]; selected['sampleMeansUs'] = [110.0] * 5
                write(file, leg)
        code, report = self.assess()
        self.assertEqual(code, 0); self.assertTrue(report['validInput']); self.assertEqual(report['performanceOutcome'], 'hold')
        self.assertEqual(report['counts'], {'pass': 4, 'hold': 1, 'inconclusive': 0})

    def test_duplicate_json_key_is_rejected(self):
        file = self.root / 'duplicate.json'; file.write_text('{"role":"A","role":"B"}')
        with self.assertRaises(ValueError): self.module.load(file)


if __name__ == '__main__':
    unittest.main()
