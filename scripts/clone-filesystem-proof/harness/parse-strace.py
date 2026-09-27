#!/usr/bin/env python3
"""Fail-closed syscall-count evidence; never runs a traced workload.

Usage: python3 parse-strace.py TRACE MANIFEST OUTPUT
TRACE: strace -f -ttt -yy -s512 -e trace=fstatfs,write -o TRACE ...
MANIFEST: operation, filesystem, role, parentPath, sourcePath (null for create),
          beginMarker="FS_SAFE_CLONE_BEGIN", endMarker="FS_SAFE_CLONE_END".

Each marker must be one successful fd1 write of the marker plus a newline.
Paths are canonical absolute POSIX spellings recorded on the traced host;
they are never resolved against the machine reading the evidence. OUTPUT
must be new. All admitted input bytes and this parser's source are hashed.
The workload owner must independently bound capture and prove settlement.
"""

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys


TRACE_LIMIT = 8 * 1024 * 1024
MANIFEST_LIMIT = 64 * 1024
SOURCE_LIMIT = 1024 * 1024
MARKERS = {"begin": "FS_SAFE_CLONE_BEGIN", "end": "FS_SAFE_CLONE_END"}
OPERATIONS = {"createCloneSource", "copyTree-empty", "copyTree-small-nested"}
FS_TYPES = {"xfs": ("XFS_SUPER_MAGIC", 0x58465342),
            "btrfs": ("BTRFS_SUPER_MAGIC", 0x9123683E)}
PREFIX = re.compile(
    r"^[ \t]*(?:(?:\[pid\s+(?P<bracket>[1-9][0-9]*)\]|(?P<plain>[1-9][0-9]*))\s+)?"
    r"(?P<time>[0-9]+\.[0-9]{6})\s+(?P<body>.+)$"
)
ENTRY = re.compile(r"^(?P<name>[a-zA-Z_][a-zA-Z_0-9]*)\(")
RESUME = re.compile(r"^<\.\.\. (?P<name>[a-zA-Z_][a-zA-Z_0-9]*) resumed>(?P<tail>.*)$")
COMPLETE = re.compile(r"^(?P<name>write|fstatfs)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$")
EXIT = re.compile(r"^\+\+\+ exited with (?P<code>[0-9]+) \+\+\+$")
SIGNAL = re.compile(r"^--- SIG[A-Z0-9]+(?: \{.*\})? ---$")
NOTICE = re.compile(r"^strace: Process (?P<tid>[1-9][0-9]*) (?P<action>attached|detached)$")
QUOTED = re.compile(r'^"(?P<text>(?:[^"\\]|\\.)*)"(?P<truncated>\.\.\.)?\s*,\s*(?P<count>[0-9]+)$')


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def problem(report, code, message, line=None):
    item = {"code": code, "message": str(message)}
    if line is not None:
        item["line"] = line
    report["errors"].append(item)


def snapshot(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def read_input(path, limit, metadata):
    metadata.update(path=str(path), limitBytes=limit, bytes=None, sha256=None)
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        metadata["bytes"] = before.st_size
        require(stat.S_ISREG(before.st_mode), "input is not a regular file")
        require(before.st_size <= limit, f"input exceeds {limit} byte limit")
        chunks, length = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, limit + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            require(length <= limit, f"input grew beyond {limit} byte limit")
        data = b"".join(chunks)
        metadata.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        require(snapshot(before) == snapshot(os.fstat(descriptor)), "input changed while being read")
        require(snapshot(before) == snapshot(os.lstat(path)), "input pathname changed while being read")
        require(len(data) == before.st_size, "input read was incomplete")
        return data
    finally:
        os.close(descriptor)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise EvidenceError(f"non-JSON numeric constant: {value}")


def canonical_path(value, field):
    require(isinstance(value, str) and value.startswith("/") and not value.startswith("//"),
            f"{field} must be an absolute POSIX path")
    require(posixpath.normpath(value) == value, f"{field} is not a canonical path spelling")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value),
            f"{field} contains control characters")
    require(not value.endswith(" (deleted)"), f"{field} describes a deleted descriptor")
    value.encode("utf-8", "strict")
    return value


def read_manifest(data):
    manifest = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant)
    require(isinstance(manifest, dict), "manifest must be a JSON object")
    for name in ("operation", "filesystem", "role", "parentPath", "sourcePath",
                 "beginMarker", "endMarker"):
        require(name in manifest, f"missing manifest field: {name}")
    require(manifest["operation"] in OPERATIONS, "unknown operation")
    require(manifest["filesystem"] in FS_TYPES, "unknown filesystem")
    require(manifest["role"] in ("A", "B"), "role must be A or B")
    canonical_path(manifest["parentPath"], "parentPath")
    if manifest["operation"] == "createCloneSource":
        require(manifest["sourcePath"] is None, "createCloneSource sourcePath must be null")
    else:
        canonical_path(manifest["sourcePath"], "sourcePath")
        require(manifest["sourcePath"] != manifest["parentPath"], "parent and source paths must differ")
    for kind, marker in MARKERS.items():
        require(manifest[kind + "Marker"] == marker, f"unexpected {kind}Marker")
    return manifest


def c_bytes(text):
    """Decode strace's byte-oriented C escapes without Python escape guessing."""
    result, index = bytearray(), 0
    simple = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
              "\\": 92, '"': 34}
    while index < len(text):
        char = text[index]
        index += 1
        if char != "\\":
            require(ord(char) >= 32 and ord(char) != 127, "raw control character in strace string")
            result.extend(char.encode("utf-8", "strict"))
            continue
        require(index < len(text), "incomplete C escape")
        char = text[index]
        index += 1
        if char in simple:
            result.append(simple[char])
        elif char in "01234567":
            digits = char
            while index < len(text) and len(digits) < 3 and text[index] in "01234567":
                digits += text[index]
                index += 1
            value = int(digits, 8)
            require(value <= 255, "C octal escape is not a byte")
            result.append(value)
        elif char == "x":
            digits = text[index:index + 2]
            require(re.fullmatch(r"[0-9a-fA-F]{2}", digits), "invalid C hex byte escape")
            result.append(int(digits, 16))
            index += 2
        else:
            raise EvidenceError(f"unknown C escape: \\{char}")
    return bytes(result)


def fd_argument(arguments):
    match = re.match(r"^(?P<fd>[0-9]+)", arguments)
    require(match is not None, "missing numeric file descriptor")
    index, annotation = match.end(), None
    if index < len(arguments) and arguments[index] == "<":
        start, depth = index + 1, 1
        index += 1
        while index < len(arguments) and depth:
            char = arguments[index]
            if char == "\\":
                require(index + 1 < len(arguments), "incomplete descriptor escape")
                index += 2
                continue
            if char == "<":
                depth += 1
            elif char == ">" and arguments[index - 1] != "-":
                depth -= 1
            index += 1
        require(depth == 0, "incomplete -yy descriptor annotation")
        annotation = arguments[start:index - 1]
    rest = arguments[index:]
    require(rest.startswith(","), "unparseable descriptor argument")
    return int(match.group("fd")), annotation, rest[1:].lstrip()


def record(tid, timestamp, number, name, text):
    return {"tid": tid, "syscall": name, "startLine": number, "endLine": None,
            "startTimestamp": timestamp, "endTimestamp": None,
            "unfinished": False, "text": text, "complete": False}


def parse_trace(data, report):
    require(data and data.endswith(b"\n"), "trace is empty or has a truncated final line")
    require(b"\x00" not in data, "trace contains NUL bytes")
    text = data.decode("utf-8", "strict")
    pending, records, tids, exits = {}, [], set(), {}
    last_time = {}
    for number, line in enumerate(text.split("\n")[:-1], 1):
        notice = NOTICE.fullmatch(line)
        if notice:
            tid = notice.group("tid")
            tids.add(tid)
            if notice.group("action") == "detached":
                problem(report, "detached", f"traced TID {tid} detached", number)
            continue
        prefix = PREFIX.fullmatch(line)
        if not prefix:
            problem(report, "trace-format", "unrecognized or un-timestamped trace record", number)
            continue
        tid = prefix.group("bracket") or prefix.group("plain") or "main"
        timestamp, body = prefix.group("time"), prefix.group("body")
        tids.add(tid)
        microseconds = int(timestamp.replace(".", ""))
        if tid in last_time and microseconds < last_time[tid]:
            problem(report, "timestamp-order", f"timestamp moved backwards for TID {tid}", number)
        last_time[tid] = microseconds
        if tid in exits:
            problem(report, "record-after-exit", f"record follows terminal exit for TID {tid}", number)
        exit_match = EXIT.fullmatch(body)
        if exit_match:
            code = int(exit_match.group("code"))
            exits[tid] = {"tid": tid, "line": number, "exitCode": code}
            if code != 0:
                problem(report, "nonzero-exit", f"TID {tid} exited with {code}", number)
            if tid in pending:
                problem(report, "exit-with-pending-call", f"TID {tid} exited with an unfinished syscall", number)
            continue
        if SIGNAL.fullmatch(body):
            continue
        if body.startswith("+++ killed by "):
            problem(report, "killed", f"TID {tid}: {body}", number)
            continue
        resumed = RESUME.fullmatch(body)
        if resumed:
            call = pending.pop(tid, None)
            if call is None:
                problem(report, "orphan-resume", f"TID {tid} has no pending syscall", number)
                continue
            if resumed.group("name") != call["syscall"]:
                problem(report, "mismatched-resume", f"TID {tid} resumed a different syscall", number)
                continue
            call["text"] += resumed.group("tail")
            call.update(endLine=number, endTimestamp=timestamp, complete=True)
            continue
        entry = ENTRY.match(body)
        if not entry or entry.group("name") not in ("write", "fstatfs"):
            problem(report, "unexpected-record", f"unrecognized filtered record for TID {tid}", number)
            continue
        if tid in pending:
            problem(report, "overwritten-pending-call", f"TID {tid} entered a syscall before its prior call resumed", number)
        name = entry.group("name")
        unfinished = body.endswith("<unfinished ...>")
        call = record(tid, timestamp, number, name,
                      body[:-len("<unfinished ...>")].rstrip() if unfinished else body)
        records.append(call)
        if unfinished:
            call["unfinished"] = True
            pending[tid] = call
        else:
            call.update(endLine=number, endTimestamp=timestamp, complete=True)
    for call in records:
        if not call["complete"]:
            problem(report, "incomplete-call", f"TID {call['tid']} has an incomplete {call['syscall']}", call["startLine"])
    report["traceSummary"] = {"lines": len(text.split("\n")) - 1,
                              "tids": sorted(tids), "exits": list(exits.values()),
                              "syscalls": len(records)}
    # Missing terminal records make a partially captured process indistinguishable
    # from a complete capture, even when the marker pair happened to survive.
    for tid in sorted(tids - exits.keys()):
        problem(report, "missing-exit", f"no successful terminal exit record for TID {tid}")
    return records


def decode_calls(records, report):
    markers = {"begin": [], "end": []}
    for call in records:
        if not call["complete"]:
            continue
        try:
            parsed = COMPLETE.fullmatch(call["text"])
            require(parsed is not None and parsed.group("name") == call["syscall"],
                    "malformed or incompletely resumed syscall")
            call["arguments"], call["result"] = parsed.group("args"), parsed.group("result")
            if call["syscall"] != "write":
                continue
            fd, annotation, rest = fd_argument(call["arguments"])
            call.update(fd=fd, descriptorAnnotation=annotation)
            quoted = QUOTED.fullmatch(rest)
            require(quoted is not None, "write buffer is not a decoded C string with an exact length")
            payload, requested = c_bytes(quoted.group("text")), int(quoted.group("count"))
            truncated = quoted.group("truncated") is not None
            require(len(payload) <= 512, "write string exceeds declared strace -s512 limit")
            require((truncated and requested > len(payload)) or (not truncated and requested == len(payload)),
                    "write buffer length disagrees with requested byte count")
            result = call["result"]
            if re.fullmatch(r"[0-9]+", result):
                require(int(result) <= requested, "write returned more bytes than requested")
            else:
                require(re.fullmatch(r"-1 E[A-Z0-9_]+ \([^\n]*\)", result)
                        or re.fullmatch(r"\? ERESTART(?:SYS|NOINTR|NOHAND|_RESTARTBLOCK) \([^\n]*\)", result),
                        "unrecognized write return syntax")
            if fd != 1:
                continue
            for kind, logical in MARKERS.items():
                if logical.encode("ascii") not in payload:
                    continue
                markers[kind].append(call)
                expected = (logical + "\n").encode("ascii")
                require(fd == 1 and annotation is not None, "marker must use fd1 with -yy annotation")
                require(not truncated and payload == expected, "malformed marker payload; exact marker plus newline required")
                require(requested == len(expected) and call["result"] == str(len(expected)),
                        "marker write was not a successful full-length write")
                call["marker"] = kind
                call["markerBytes"] = requested
        except (EvidenceError, UnicodeError) as error:
            call["parseError"] = str(error)
            problem(report, "syscall-format", str(error), call["startLine"])
    return markers


def call_details(call):
    names = ("tid", "syscall", "startLine", "endLine", "startTimestamp", "endTimestamp",
             "unfinished", "complete", "fd", "descriptorAnnotation", "result", "parseError",
             "marker", "markerBytes")
    return {name: call[name] for name in names if name in call}


def value_parts(text):
    """Split strace structure/array contents, rejecting extra outer delimiters."""
    parts, nesting, start = [], [], 0
    for index, char in enumerate(text):
        if char in "{[":
            nesting.append(char)
        elif char in "}]":
            require(nesting and nesting.pop() == {"}": "{", "]": "["}[char],
                    "fstatfs result structure is unbalanced")
        elif char == "," and not nesting:
            parts.append(text[start:index].strip())
            start = index + 1
    require(not nesting, "fstatfs result structure is incomplete")
    parts.append(text[start:].strip())
    require(all(parts), "empty fstatfs field or array element")
    return parts


def validate_value(text, depth=0):
    require(depth < 8, "unexpectedly deep fstatfs result structure")
    if text.startswith("{") and text.endswith("}"):
        fields = {}
        parts = value_parts(text[1:-1])
        for index, part in enumerate(parts):
            if part == "...":
                require(index == len(parts) - 1, "misplaced fstatfs abbreviation")
                continue
            field = re.fullmatch(r"([a-zA-Z_][a-zA-Z_0-9]*)=(.+)", part)
            require(field is not None, "malformed fstatfs field")
            name, value = field.group(1), field.group(2).strip()
            require(name not in fields, "duplicate fstatfs field")
            validate_value(value, depth + 1)
            fields[name] = value
        return fields
    if text.startswith("[") and text.endswith("]"):
        parts = value_parts(text[1:-1])
        for index, part in enumerate(parts):
            if part == "...":
                require(index == len(parts) - 1, "misplaced fstatfs array abbreviation")
            else:
                validate_value(part, depth + 1)
        return None
    scalar = r"(?:-?(?:0x[0-9a-fA-F]+|[0-9]+)|[A-Z_][A-Z_0-9]*)"
    require(re.fullmatch(scalar + r"(?:\|" + scalar + r")*", text), "malformed fstatfs field value")
    return None


def statfs_fields(call, manifest):
    require("arguments" in call, "fstatfs arguments were not completely parsed")
    fd, annotation, structure = fd_argument(call["arguments"])
    call.update(fd=fd, descriptorAnnotation=annotation)
    require(annotation is not None, "fstatfs has no -yy descriptor path")
    path = c_bytes(annotation).decode("utf-8", "strict")
    canonical_path(path, "fstatfs descriptor path")
    require(call["result"] == "0", "fstatfs did not return an unqualified success (0)")
    require(structure.startswith("{") and structure.endswith("}"), "fstatfs result structure is missing")
    fields = validate_value(structure)
    magic = fields.get("f_type", "")
    require(re.fullmatch(r"[A-Z_0-9]+|0x[0-9a-fA-F]+", magic),
            "fstatfs filesystem magic is missing or unknown")
    symbolic, numeric = FS_TYPES[manifest["filesystem"]]
    require(magic == symbolic or (magic.startswith("0x") and int(magic, 16) == numeric),
            "fstatfs filesystem magic differs from manifest")
    if path == manifest["parentPath"]:
        attribution = "parent"
    elif manifest["sourcePath"] is not None and path == manifest["sourcePath"]:
        attribution = "source"
    else:
        raise EvidenceError(f"unknown fstatfs descriptor path: {path}")
    return {"fd": fd, "path": path, "filesystemMagic": magic, "attribution": attribution}


def evaluate(records, markers, manifest, report):
    expected = {"parent": 3 if manifest["role"] == "A" else 2,
                "source": 0 if manifest["operation"] == "createCloneSource" else 1}
    expected["total"] = expected["parent"] + expected["source"]
    report["counts"] = {"parent": 0, "source": 0, "total": 0, "insideAttempts": 0,
                        "outsideAttempts": 0, "boundaryOverlaps": 0, "expected": expected}
    report["markers"] = {kind: [call_details(call) for call in calls]
                         for kind, calls in markers.items()}
    good_markers = True
    for kind, calls in markers.items():
        if len(calls) != 1 or calls[0].get("marker") != kind:
            problem(report, "marker-count", f"expected exactly one valid {kind} marker; observed {len(calls)} candidates")
            good_markers = False
    if not good_markers:
        return
    begin, end = markers["begin"][0], markers["end"][0]
    if begin["tid"] != end["tid"] or begin.get("descriptorAnnotation") != end.get("descriptorAnnotation"):
        problem(report, "marker-writer", "begin/end markers differ in TID or fd1 descriptor annotation")
        return
    if begin["endLine"] >= end["startLine"]:
        problem(report, "marker-order", "marker writes are reversed, overlapping, or unordered")
        return
    report["span"] = {"beginCompletedLine": begin["endLine"], "endStartedLine": end["startLine"],
                      "markerTid": begin["tid"], "ordering": "trace line order; strict interior"}
    call_items = {item["startLine"]: item for item in report["calls"]}
    for call in records:
        if call["syscall"] != "fstatfs":
            continue
        item = call_items[call["startLine"]]
        if not call["complete"]:
            continue
        start, finish = call["startLine"], call["endLine"]
        overlap = any(start <= edge["endLine"] and finish >= edge["startLine"]
                      for edge in (begin, end))
        if overlap:
            item["scope"] = "marker-overlap"
            report["counts"]["boundaryOverlaps"] += 1
            problem(report, "boundary-overlap", "fstatfs overlaps a marker write interval", start)
            continue
        if not (begin["endLine"] < start and finish < end["startLine"]):
            item.update(scope="outside", ok=None)
            report["counts"]["outsideAttempts"] += 1
            continue
        item["scope"] = "inside"
        report["counts"]["insideAttempts"] += 1
        try:
            item.update(statfs_fields(call, manifest))
            item["ok"] = True
            report["counts"][item["attribution"]] += 1
            report["counts"]["total"] += 1
        except (EvidenceError, UnicodeError) as error:
            item["error"] = str(error)
            problem(report, "fstatfs-admission", str(error), start)
        finally:
            item.update(call_details(call))
    for kind in ("parent", "source", "total"):
        if report["counts"][kind] != expected[kind]:
            problem(report, "count-mismatch", f"{kind}: expected {expected[kind]}, observed {report['counts'][kind]}")


def save_output(path, report):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    if len(sys.argv) != 4:
        print("usage: python3 parse-strace.py TRACE MANIFEST OUTPUT", file=sys.stderr)
        return 2
    trace_path, manifest_path, output_path = (Path(value).absolute() for value in sys.argv[1:])
    source_path = Path(__file__).resolve()
    report = {"schema": 1, "ok": False, "status": "fail", "errors": [], "manifest": None,
              "provenance": {"source": {}, "trace": {}, "manifest": {}},
              "markers": {"begin": [], "end": []}, "counts": None, "calls": [],
              "proof": "fstatfs counts only; no elapsed-time or process-settlement claim"}
    inputs = {}
    for name, path, limit in (("source", source_path, SOURCE_LIMIT),
                              ("trace", trace_path, TRACE_LIMIT),
                              ("manifest", manifest_path, MANIFEST_LIMIT)):
        try:
            require(output_path.resolve() != path.resolve(), "output overlaps an input path")
            inputs[name] = read_input(path, limit, report["provenance"][name])
        except (OSError, EvidenceError) as error:
            problem(report, name + "-input", str(error))
    manifest = None
    if "manifest" in inputs:
        try:
            manifest = read_manifest(inputs["manifest"])
            report["manifest"] = manifest
        except (ValueError, TypeError, UnicodeError) as error:
            problem(report, "manifest", str(error))
    if "trace" in inputs:
        try:
            records = parse_trace(inputs["trace"], report)
            markers = decode_calls(records, report)
            report["markers"] = {kind: [call_details(call) for call in calls]
                                 for kind, calls in markers.items()}
            report["calls"] = [{**call_details(call), "raw": call["text"],
                                "scope": "unclassified", "ok": False}
                               for call in records if call["syscall"] == "fstatfs"]
            if manifest is not None:
                evaluate(records, markers, manifest, report)
        except (EvidenceError, UnicodeError) as error:
            problem(report, "trace", str(error))
    report["ok"] = not report["errors"] and report["counts"] is not None
    report["status"] = "pass" if report["ok"] else "fail"
    try:
        save_output(output_path, report)
    except (OSError, ValueError) as error:
        problem(report, "output", str(error))
        report.update(ok=False, status="fail")
        print(json.dumps(report, sort_keys=True, ensure_ascii=True), file=sys.stderr)
        return 1
    print(json.dumps({"schema": 1, "ok": report["ok"], "status": report["status"],
                      "output": str(output_path), "counts": report["counts"],
                      "errors": report["errors"]}, sort_keys=True), flush=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
