#!/usr/bin/env python3
"""Offline regression checks for structured eventfd lifetime annotations."""

import types
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "harness/compare-syscalls.py"
PARSER = types.ModuleType("eventfd_candidate")
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), PARSER.__dict__)


def rich(count="0", identity="29", semaphore="0"):
    return "{eventfd-count=" + count + ", eventfd-id=" + identity + ", eventfd-semaphore=" + semaphore + "}"


def lifetimes(annotations, close_after=None):
    rows = []
    for index, annotation in enumerate(annotations):
        rows.append('write(19<' + annotation + '>, "\\1\\0\\0\\0\\0\\0\\0\\0", 8) = 8')
        if index == close_after:
            rows.append("close(19<" + annotation + ">) = 0")
    rows.append("+++ exited with 0 +++")
    data = "".join("901 1." + str(index + 1).zfill(6) + " " + row + "\n" for index, row in enumerate(rows))
    records, _ = PARSER.parse_trace(data.encode("ascii"))
    begin = {"tid": "901", "startLine": 100, "endLine": 100}
    end = {"tid": "901", "startLine": 200, "endLine": 200}
    return PARSER.annotate_lifetimes(records, begin, end)[0]


class EventfdAnnotations(unittest.TestCase):
    def test_count_changes_preserve_each_raw_observation(self):
        annotations = [rich("0"), rich("0x1"), rich("0x2"), rich("0")]
        owners = lifetimes(annotations)
        self.assertEqual(len(owners), 1)
        owner = owners[0]
        self.assertEqual(owner["openedPath"], annotations[0])
        self.assertEqual(owner["path"], annotations[0])
        self.assertEqual(owner["references"], [1, 2, 3, 4])
        self.assertEqual([item["annotation"] for item in owner["eventfdObservations"]], annotations)
        self.assertEqual([item["count"] for item in owner["eventfdObservations"]], ["0", "0x1", "0x2", "0"])
        self.assertEqual([item["line"] for item in owner["eventfdObservations"]], [1, 2, 3, 4])

    def test_identity_change_fails(self):
        with self.assertRaisesRegex(PARSER.EvidenceError, "descriptor annotation changed"):
            lifetimes([rich(), rich("0x1", identity="30")])

    def test_semaphore_change_fails(self):
        with self.assertRaisesRegex(PARSER.EvidenceError, "descriptor annotation changed"):
            lifetimes([rich(), rich("0x1", semaphore="1")])

    def test_filesystem_annotation_change_still_fails(self):
        with self.assertRaisesRegex(PARSER.EvidenceError, "descriptor annotation changed"):
            lifetimes(["/synthetic/owned", "/synthetic/replaced"])

    def test_structured_and_legacy_annotations_are_not_interchangeable(self):
        for annotations in ([rich(), "anon_inode:[eventfd]"], ["anon_inode:[eventfd]", rich()]):
            with self.subTest(annotations=annotations):
                with self.assertRaisesRegex(PARSER.EvidenceError, "descriptor annotation changed"):
                    lifetimes(annotations)

    def test_unrecognized_annotation_changes_fail(self):
        malformed = [rich("1"), rich("-1"), rich("0x10000000000000000"), rich(semaphore="2"),
                     rich()[:-1] + ", extra=0}", "/synthetic/" + rich()]
        for annotation in malformed:
            with self.subTest(annotation=annotation):
                self.assertIsNone(PARSER.eventfd_state(annotation))
                with self.assertRaisesRegex(PARSER.EvidenceError, "descriptor annotation changed"):
                    lifetimes([rich(), annotation])

    def test_close_then_reuse_starts_a_distinct_owner(self):
        owners = lifetimes([rich(), rich(identity="30")], close_after=0)
        self.assertEqual(len(owners), 2)
        self.assertEqual(owners[0]["closeLine"], 2)
        self.assertEqual(owners[0]["eventfdObservations"][-1]["line"], 2)
        self.assertEqual(owners[1]["references"], [3])
        self.assertNotEqual(owners[0]["id"], owners[1]["id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
