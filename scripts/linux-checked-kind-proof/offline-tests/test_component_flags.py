#!/usr/bin/env python3
"""Exercise the complete component shape validator with precise open flags."""

import types
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "harness/compare-syscalls.py"
PARSER = types.ModuleType("component_flags_candidate")
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), PARSER.__dict__)
ACTUAL_FLAGS = "O_RDONLY|O_LARGEFILE|O_NOFOLLOW|O_CLOEXEC|O_PATH"


def component(flags):
    path = "/synthetic/d0"
    opened = {"syscall": "openat", "arguments": ["20</synthetic>", '"d0"', flags], "result": {"value": 21},
              "resultLife": 0, "normalizedIndex": 0, "startLine": 1, "endLine": 1}
    calls = [opened]
    for line, kind in ((2, "named"), (3, "descriptor"), (4, "named"), (5, "descriptor")):
        calls.append({"syscall": "fstat" if kind == "descriptor" else "newfstatat", "result": {"value": 0},
                      "startLine": line, "endLine": line, "normalizedIndex": line - 1,
                      "metadata": {"kind": kind, "life": 0 if kind == "descriptor" else None,
                                   "path": path if kind == "named" else None, "nofollow": kind == "named",
                                   "identity": [1, 2, 3], "mode": "S_IFDIR|0755"}})
    life = {"id": 0, "openedPath": path, "openLine": 1, "closeLine": 8}
    manifest = {"descriptor": {"alias": False, "mechanism": "ENOSYS"}, "existingParentPaths": [path], "role": "B"}
    result = PARSER.checked_components(calls, [life], {"startLine": 9}, manifest)
    return opened, result


class ComponentFlags(unittest.TestCase):
    def test_actual_largefile_combination_is_retained_and_accepted(self):
        opened, (summaries, deletions) = component(ACTUAL_FLAGS)
        self.assertEqual(opened["arguments"][2], ACTUAL_FLAGS)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(deletions, [])

    def test_original_combination_remains_accepted(self):
        _, (summaries, _) = component("O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH")
        self.assertEqual(len(summaries), 1)

    def test_unsafe_or_unknown_extras_still_fail(self):
        for extra in ("O_TRUNC", "O_CREAT", "O_WRONLY", "O_RDWR", "O_APPEND", "O_TMPFILE", "O_UNKNOWN", "0x40000000"):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(PARSER.EvidenceError, "unexpected component probe flags"):
                    component(ACTUAL_FLAGS + "|" + extra)

    def test_required_capability_flags_remain_required(self):
        for removed in ("O_PATH", "O_NOFOLLOW", "O_CLOEXEC"):
            with self.subTest(removed=removed):
                with self.assertRaises(PARSER.EvidenceError):
                    component("|".join(flag for flag in ACTUAL_FLAGS.split("|") if flag != removed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
