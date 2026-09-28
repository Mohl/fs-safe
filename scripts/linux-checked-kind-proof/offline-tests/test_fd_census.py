#!/usr/bin/env python3
"""Offline checks of the out-of-span census classification boundary."""

import json
import types
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "harness/compare-syscalls.py"
PARSER = types.ModuleType("census_candidate")
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), PARSER.__dict__)


def link(target="anon_inode:[eventpoll]", fd=3, process="self", suffix="", size=4096, result=None):
    output = json.dumps(target)
    returned = str(len(target.encode("utf-8"))) if result is None else result
    return 'readlink("/proc/' + process + '/fd/' + str(fd) + suffix + '", ' + output + ', ' + str(size) + ') = ' + returned


def missing(fd=20, process="self", suffix="", errno="ENOENT", output="0x1234", size=4096):
    return 'readlink("/proc/' + process + '/fd/' + str(fd) + suffix + '", ' + output + ', ' + str(size) + ') = -1 ' + errno + ' (diagnostic)'


ENUM_OPEN = 'openat(AT_FDCWD</synthetic>, "/proc/self/fd", O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 20</proc/901/fd>'
ENUM_CLOSE = 'close(20</proc/901/fd>) = 0'
SELF_LINK = 'readlink("/proc/self", "901", 1024) = 3'


def inspect(rows, phase="before", tid="901", unfinished=False):
    trace = "".join(tid + " 1." + str(index + 1).zfill(6) + " " + row + "\n" for index, row in enumerate(rows + ["+++ exited with 0 +++"]))
    records, _ = PARSER.parse_trace(trace.encode("ascii"))
    if unfinished:
        records[-1]["endLine"] = 101
        records[-1]["unfinished"] = True
    limits = {"before": (100, 200), "inside": (0, 200), "after": (-2, 0)}
    start, stop = limits[phase]
    begin = {"tid": "901", "startLine": start, "endLine": start}
    end = {"tid": "901", "startLine": stop, "endLine": stop}
    owners, _ = PARSER.annotate_lifetimes(records, begin, end)
    return records, owners


class DescriptorCensus(unittest.TestCase):
    def test_known_anonymous_targets_are_evidence_without_owners(self):
        for phase in ("before", "after"):
            for target in ("anon_inode:[eventpoll]", "anon_inode:[io_uring]", "anon_inode:[eventfd]", "pipe:[90210]"):
                with self.subTest(phase=phase, target=target):
                    records, owners = inspect([link(target), link(target)], phase=phase)
                    self.assertEqual(owners, [])
                    self.assertTrue(all(call["fdRefs"] == call["procFdRefs"] == {} for call in records))
                    self.assertEqual([call["fdCensus"]["target"] for call in records], [target, target])
                    self.assertEqual(records[0]["fdCensus"]["result"]["value"], len(target))
                    self.assertEqual(records[0]["fdCensus"]["phase"], phase)
                    self.assertIn(target, records[0]["raw"])

    def test_decoded_literal_self_path_is_classified(self):
        records, _ = inspect([r'readlink("/proc/\163elf/fd/3", "anon_inode:[eventpoll]", 4096) = 22'])
        self.assertEqual(records[0]["fdCensus"]["path"], "/proc/self/fd/3")

    def test_numeric_leader_requires_prior_validated_self_link(self):
        with self.assertRaises(PARSER.EvidenceError):
            inspect([link(process="901")])
        records, _ = inspect([SELF_LINK, link(process="901")])
        self.assertEqual(records[-1]["fdCensus"]["path"], "/proc/901/fd/3")
        with self.assertRaises(PARSER.EvidenceError):
            inspect(['readlink("/proc/self", "902", 1024) = 3', link(process="901")])

    def test_foreign_worker_suffix_and_selected_span_fail(self):
        for rows, options in (([link(process="902")], {}), ([link()], {"tid": "902"}),
                              ([link(suffix="/child")], {}), ([link()], {"phase": "inside"}),
                              ([link()], {"unfinished": True})):
            with self.subTest(rows=rows, options=options):
                with self.assertRaises(PARSER.EvidenceError):
                    inspect(rows, **options)

    def test_filesystem_and_unknown_resource_targets_fail(self):
        for target in ("/synthetic/file", "socket:[90210]", "anon_inode:[unknown]", "pipe:[0]", "pipe:[01]"):
            with self.subTest(target=target):
                with self.assertRaises(PARSER.EvidenceError):
                    inspect([link(target)])

    def test_output_must_be_complete_consistent_and_untruncated(self):
        malformed = [link(size=22), link(result="21"), link(size=0),
                     'readlink("/proc/self/fd/3", "anon_inode:[eventpoll]"..., 4096) = 22']
        for row in malformed:
            with self.subTest(row=row):
                with self.assertRaises(PARSER.EvidenceError):
                    inspect([row])

    def test_changed_anonymous_target_or_pipe_identity_fails(self):
        for first, second in (("anon_inode:[eventpoll]", "anon_inode:[io_uring]"), ("pipe:[1]", "pipe:[2]")):
            with self.subTest(first=first, second=second):
                with self.assertRaisesRegex(PARSER.EvidenceError, "anonymous census target changed"):
                    inspect([link(first), link(second)])

    def test_later_open_cannot_reuse_observed_occupied_number(self):
        with self.assertRaisesRegex(PARSER.EvidenceError, "unretired anonymous census"):
            inspect([link(), 'openat(AT_FDCWD</synthetic>, "/synthetic/file", O_RDONLY) = 3</synthetic/file>'])

    def test_startup_ebadf_cannot_contradict_observed_occupancy(self):
        for operation in ("F_GETFD", "F_SETFD, FD_CLOEXEC"):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(PARSER.EvidenceError, "differs from its anonymous census"):
                    inspect([link(), "fcntl(3, " + operation + ") = -1 EBADF (diagnostic)"])

    def test_direct_annotation_must_agree_with_observation(self):
        with self.assertRaisesRegex(PARSER.EvidenceError, "differs from its anonymous census"):
            inspect([link("pipe:[1]"), "close(3<pipe:[2]>) = 0"])

    def test_rich_eventfd_identity_remains_exact_after_observation(self):
        rows = [link("anon_inode:[eventfd]"),
                r'write(3<{eventfd-count=0, eventfd-id=29, eventfd-semaphore=0}>, "\1\0\0\0\0\0\0\0", 8) = 8',
                r'write(3<{eventfd-count=0x1, eventfd-id=30, eventfd-semaphore=0}>, "\1\0\0\0\0\0\0\0", 8) = 8']
        with self.assertRaisesRegex(PARSER.EvidenceError, "descriptor annotation changed"):
            inspect(rows)

    def test_successful_close_retires_observed_occupancy(self):
        records, owners = inspect([link("pipe:[1]"), "close(3<pipe:[1]>) = 0",
                                   'openat(AT_FDCWD</synthetic>, "/synthetic/file", O_RDONLY) = 3</synthetic/file>'])
        self.assertEqual(len(owners), 2)
        self.assertEqual(owners[0]["closeLine"], 2)
        self.assertEqual(owners[1]["openLine"], 3)

    def test_failed_close_exec_and_atomic_replacement_do_not_retire_observation(self):
        alternatives = ["close(3<pipe:[1]>) = -1 EBADF (diagnostic)",
                        'execve("/synthetic/node", ["node"], 0x1234) = 0',
                        'dup2(4<pipe:[2]>, 3<pipe:[1]>) = 3<pipe:[2]>']
        for operation in alternatives:
            with self.subTest(operation=operation):
                with self.assertRaises(PARSER.EvidenceError):
                    inspect([link("pipe:[1]"), operation,
                             'openat(AT_FDCWD</synthetic>, "/synthetic/file", O_RDONLY) = 3</synthetic/file>'])

    def test_closed_enumeration_probe_has_exact_retirement_evidence(self):
        for phase in ("before", "after"):
            records, owners = inspect([ENUM_OPEN, ENUM_CLOSE, missing()], phase=phase)
            census = records[-1]["fdCensus"]
            self.assertEqual(census["kind"], "closed-enumeration-directory")
            self.assertEqual(census["retiredOwner"], {"life": owners[0]["id"], "openLine": 1, "closeLine": 2})
            self.assertEqual(census["result"]["errno"], "ENOENT")
            self.assertEqual(census["outputBuffer"], "0x1234")
            self.assertEqual(records[-1]["procFdRefs"], {})

    def test_enoent_requires_latest_closed_enumeration_owner(self):
        alternatives = [[missing()], [ENUM_OPEN, missing()],
                        [ENUM_OPEN, ENUM_CLOSE, 'openat(AT_FDCWD</synthetic>, "/synthetic/file", O_RDONLY) = 20</synthetic/file>',
                         'close(20</synthetic/file>) = 0', missing()],
                        [ENUM_OPEN, 'execve("/synthetic/node", ["node"], 0x1234) = 0', missing()]]
        for rows in alternatives:
            with self.subTest(rows=rows):
                with self.assertRaises(PARSER.EvidenceError):
                    inspect(rows)

    def test_enoent_does_not_excuse_other_errno_output_path_or_thread(self):
        alternatives = [(missing(errno="EACCES"), {}), (missing(output='"untouched"'), {}),
                        (missing(size=0), {}), (missing(process="902"), {}),
                        (missing(suffix="/child"), {}), (missing(), {"tid": "902"}),
                        (missing(), {"phase": "inside"}), (missing(), {"unfinished": True})]
        for row, options in alternatives:
            with self.subTest(row=row, options=options):
                with self.assertRaises(PARSER.EvidenceError):
                    inspect([ENUM_OPEN, ENUM_CLOSE, row], **options)

    def test_enoent_does_not_retire_anonymous_occupancy(self):
        with self.assertRaises(PARSER.EvidenceError):
            inspect([ENUM_OPEN, ENUM_CLOSE, link(fd=20), missing()])


if __name__ == "__main__":
    unittest.main(verbosity=2)
