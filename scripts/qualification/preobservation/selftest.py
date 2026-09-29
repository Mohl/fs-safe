#!/usr/bin/env python3
"""Synthetic parser/inference checks only. Never launches product code."""
import copy
import io
import math
import os
from pathlib import Path
import runpy
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, PACKET_HASHES, digest, read, reserve_budget, run, write
from experiment import NAMES, analyze_calibration, calibration_schedule, control_bound, parse_iostat
from stage2 import observed_run


class CarrierTests(unittest.TestCase):
    def test_resource_budget_refuses_launch_without_shortening_timeout(self):
        with patch('common.time.monotonic', return_value=100), patch('common.subprocess.Popen') as launch:
            reserve_budget(710, 600)
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
                run(temporary, 'unlaunched', ['synthetic-node'], timeout=600, deadline=709)
            launch.assert_not_called()

    def test_collector_retains_partial_failed_consumers(self):
        with tempfile.TemporaryDirectory() as temporary:
            top = Path(temporary)
            evidence, workspace, runtime = top / 'evidence', top / 'workspace', top / 'runtime'
            runtime.mkdir()
            for arm in ['A', 'B']:
                consumer = runtime / ('preobservation-consumer-' + arm)
                (consumer / 'node_modules').mkdir(parents=True)
                (consumer / 'node_modules/partial.node').write_bytes(b'synthetic incomplete install')
            with patch.dict(os.environ, EVIDENCE_ROOT=str(evidence), GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(runtime)):
                prepare = runpy.run_path(str(HERE / 'prepare.py'))
                prepare['collect']()
            for arm in ['A', 'B']:
                source = runtime / ('preobservation-consumer-' + arm) / 'node_modules/partial.node'
                self.assertEqual(read(evidence / arm / 'consumer-final-files.json')['node_modules/partial.node'], digest(source))
                with tarfile.open(evidence / arm / 'consumer-final.tar.gz') as archive:
                    self.assertEqual(archive.extractfile('consumer/node_modules/partial.node').read(), source.read_bytes())
            self.assertIn('A/consumer-final.tar.gz', read(evidence / 'SHA256.json'))

    def test_stage_two_receipts_forward_calls_and_preserve_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ['success', 'failure', 'timeout']:
                report = directory / (kind + '.json')
                command = ['synthetic-node', str(HERE / 'frozen/measure.mjs'), 'synthetic-expected.json', str(report)]
                stdout, stderr = io.StringIO(), io.StringIO()
                stdout.name, stderr.name = str(report.with_suffix('.stdout')), str(report.with_suffix('.stderr'))
                kwargs = dict(cwd='synthetic-consumer', env={'SYNTHETIC': 'unchanged'}, stdout=stdout, stderr=stderr,
                              timeout=600, check=False)
                result = subprocess.CompletedProcess(command, 7 if kind == 'failure' else 0)
                timeout = subprocess.TimeoutExpired(command, 600)
                def original(*received_args, **received_kwargs):
                    self.assertIs(received_args[0], command)
                    for key in kwargs:
                        self.assertIs(received_kwargs[key], kwargs[key])
                    if kind == 'timeout':
                        raise timeout
                    return result
                if kind == 'timeout':
                    with self.assertRaises(subprocess.TimeoutExpired) as raised:
                        observed_run(original, command, **kwargs)
                    self.assertIs(raised.exception, timeout)
                else:
                    self.assertIs(observed_run(original, command, **kwargs), result)
                invocation = read(report.with_suffix('.command.json'))
                terminal = read(report.with_suffix('.terminal.json'))
                self.assertEqual(invocation['argv'], command)
                self.assertEqual(terminal['returncode'], None if kind == 'timeout' else result.returncode)
                self.assertEqual(terminal['timedOut'], kind == 'timeout')
                self.assertEqual(terminal['cleanupReceipt'], '../qualification.terminal.json')
                self.assertEqual(terminal['expectedInheritedProcessGroupId'], invocation['driverProcessGroupId'])

    def test_environment_parser_rejects_missing_or_invalid_intervals(self):
        header = 'disk0 cpu load average\nKB/t tps MB/s us sy id 1m 5m 15m\n'
        interval = '64 2 0.1 10 10 80 1.0 2.0 3.0\n'
        raw = header + '64 2 0.1 50 50 0 99 99 99\n' + interval * 6
        self.assertTrue(parse_iostat(raw, 4)['passed'])
        self.assertTrue(parse_iostat(raw.replace(interval, '64 2 0.1 10 15 75 2 2 3\n'), 4)['passed'])
        self.assertFalse(parse_iostat(raw.replace(interval, '64 2 0.1 20 20 60 1 2 3\n', 1), 4)['passed'])
        self.assertFalse(parse_iostat(raw.replace(interval, '64 2 0.1 10 10 80 2.01 2 3\n', 1), 4)['passed'])
        for invalid in [header + interval * 6, header + interval * 8, raw.replace('MB/s', 'MB'), raw.replace('0.1', 'nan', 1)]:
            with self.assertRaises(ValueError):
                parse_iostat(invalid, 4)

    def test_balanced_same_artifact_schedule_and_original_bounds(self):
        jobs = calibration_schedule()
        self.assertEqual(len(jobs), 24)
        self.assertEqual({job['arm'] for job in jobs}, {'A'})
        self.assertEqual([job['role'] for job in jobs[:4]], list('BAAB'))
        self.assertEqual(len({job['file'] for job in jobs}), 24)
        self.assertTrue(control_bound([0.0] * 12)['passed'])
        self.assertFalse(control_bound([math.log(1.06)] * 12)['passed'])
        self.assertFalse(control_bound([-math.log(1.06)] * 12)['passed'])
        self.assertFalse(control_bound([math.log(0.8), math.log(1.25)] * 6)['passed'])

    def test_analyzer_checks_every_report_and_endpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            expected = dict(packageVersion='synthetic', nativeSha256='a' * 64)
            write(output / 'expected-A.json', expected)
            write(output / 'plan.json', dict(jobs=calibration_schedule(), packetHashes=PACKET_HASHES,
                  expected=expected, node='synthetic-node', nodeSha256='b' * 64))
            report = dict(schema=1, campaign='pr770-preobservation-v1', node='v24.21.0', nodePath='synthetic-node',
                nodeSha256='b' * 64, mode='require', cleanup='complete', platform='darwin', arch='arm64',
                probeSha256=PACKET_HASHES['measure.mjs'], packageVersion='synthetic',
                native=dict(sha256='a' * 64, cache=True, osImage=True, path='synthetic-addon'),
                samples=8, iterations=50, warmups=5, apiPath='synthetic-api', apiSha256='c' * 64,
                distSha256='d' * 64, cpu='synthetic-cpu', rows=[dict(name=name, iterations=50, warmups=5,
                verifiedCalls=405, sampleMeansUs=[1.0] * 8) for name in NAMES])
            for job in calibration_schedule():
                write(output / job['file'], report)
            self.assertTrue(analyze_calibration(output)['controlsCleared'])
            file = output / calibration_schedule()[-1]['file']
            for mutation in ['native', 'skip', 'missing']:
                changed = copy.deepcopy(report)
                if mutation == 'native':
                    changed['native']['sha256'] = 'wrong'
                elif mutation == 'skip':
                    changed['rows'][0]['skipped'] = 'unexpected'
                else:
                    changed['rows'].pop()
                file.unlink()
                write(file, changed)
                with self.assertRaises(ValueError):
                    analyze_calibration(output)


if __name__ == '__main__':
    unittest.main()
