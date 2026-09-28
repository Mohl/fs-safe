#!/usr/bin/env python3
"""Check exact fixture-parent substitution and its invocation/layout bounds."""

from copy import deepcopy
import types
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "harness/compare-syscalls.py"
PARSER = types.ModuleType("fixture_parent_candidate")
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), PARSER.__dict__)
BASE = "/synthetic/private-fixtures"


def bindings(suffix="AbC123", mechanism="ENOSYS"):
    parent = BASE + "/fs-safe-checked-kind-" + suffix
    argv = ["/packet/harness/syscall-probe.mjs", "/consumer", BASE, "enosys-depth1", "22", "/manifest.json", "/proof.json"]
    command = ["/node", *argv]
    if mechanism != "openat2":
        command = ["/deny-openat2", mechanism, *command]
    return parent, {"rootPath": parent + "/row-0", "outsidePath": parent + "/outside-0",
                    "mechanism": mechanism, "launch": {"argv": argv}}, {"command": command}


class FixtureParent(unittest.TestCase):
    def test_only_valid_exact_differing_parents_share_the_token(self):
        first, left, left_launch = bindings("yEWVol")
        second, right, right_launch = bindings("TZUfx3")
        self.assertNotEqual(first, second)
        self.assertEqual(PARSER.normalize_fixture_parent(first, left, left_launch), "$FIXTURE_PARENT")
        self.assertEqual(PARSER.normalize_fixture_parent(second, right, right_launch), "$FIXTURE_PARENT")

    def test_kernel_invocation_base_binding_uses_its_own_offset(self):
        parent, manifest, launch = bindings(mechanism="openat2")
        self.assertEqual(PARSER.normalize_fixture_parent(parent, manifest, launch), "$FIXTURE_PARENT")

    def test_parents_siblings_descendants_foreign_and_traversal_stay_literal(self):
        parent, manifest, launch = bindings()
        values = [BASE, "/synthetic", "/", parent + "/row-0", parent + "/outside-0", parent + "/child",
                  parent + "suffix", BASE + "/fs-safe-checked-kind-XyZ789", "/foreign" + parent,
                  parent + "/../fs-safe-checked-kind-AbC123", parent + "/.", parent + "/",
                  BASE + "/unrelated/../fs-safe-checked-kind-AbC123"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(PARSER.normalize_fixture_parent(value, manifest, launch), value)

    def test_mismatched_root_outside_parent_fails(self):
        parent, manifest, launch = bindings()
        manifest["outsidePath"] = BASE + "/fs-safe-checked-kind-XyZ789/outside-0"
        with self.assertRaises(PARSER.EvidenceError):
            PARSER.normalize_fixture_parent(parent, manifest, launch)

    def test_wrong_generated_children_or_workspace_name_fail(self):
        for field, replacement in (("rootPath", "/root-0"), ("rootPath", "/row-1"), ("outsidePath", "/outside-1")):
            with self.subTest(field=field, replacement=replacement):
                parent, manifest, launch = bindings()
                manifest[field] = parent + replacement
                with self.assertRaises(PARSER.EvidenceError):
                    PARSER.normalize_fixture_parent(parent, manifest, launch)
        for suffix in ("", "abcde", "abcdefg", "abcde-", "abcde_"):
            with self.subTest(suffix=suffix):
                parent, manifest, launch = bindings(suffix)
                with self.assertRaises(PARSER.EvidenceError):
                    PARSER.normalize_fixture_parent(parent, manifest, launch)

    def test_base_argument_must_match_both_invocations_and_parent(self):
        for mode in ("manifest", "launcher", "both", "missing"):
            with self.subTest(mode=mode):
                parent, manifest, launch = bindings()
                if mode in ("manifest", "both"):
                    manifest["launch"]["argv"][2] = "/foreign/private-fixtures"
                if mode in ("launcher", "both"):
                    launch["command"][5] = "/foreign/private-fixtures"
                if mode == "missing":
                    manifest["launch"]["argv"] = []
                with self.assertRaises(PARSER.EvidenceError):
                    PARSER.normalize_fixture_parent(parent, manifest, launch)

    def test_noncanonical_fixture_or_base_bindings_fail(self):
        parent, original, launch = bindings()
        for field in ("rootPath", "outsidePath"):
            with self.subTest(field=field):
                manifest = deepcopy(original)
                manifest[field] = parent + "/../fs-safe-checked-kind-AbC123/" + ("row-0" if field == "rootPath" else "outside-0")
                candidate = str(Path(manifest["rootPath"]).parent)
                with self.assertRaises(PARSER.EvidenceError):
                    PARSER.normalize_fixture_parent(candidate, manifest, launch)
        original["launch"]["argv"][2] = BASE + "/."
        with self.assertRaises(PARSER.EvidenceError):
            PARSER.normalize_fixture_parent(parent, original, launch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
