#!/usr/bin/env python3
"""Compare one frozen A/B public-call trace pair; never run a workload.

Usage: compare-syscalls.py TRACE_A MANIFEST_A PROOF_A TRACE_B MANIFEST_B PROOF_B OUTPUT
Capture: strace -f -ttt -yy -v -e abbrev=execve,execveat -s1024 -e trace=%file,fstat,close,write,fchmod,fsync,fdatasync,dup,dup2,dup3,fcntl
The output must be new. Every input and this source are hashed. This is an
untimed structural proof, not process settlement or a latency measurement.
"""

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys

TRACE_LIMIT = 32 * 1024 * 1024
JSON_LIMIT = 128 * 1024
SOURCE_LIMIT = 1024 * 1024
COMMITS = {"A": "4332074713961c7b06998bc0c594f9fab38f0bb2",
           "B": "704f586045a97144ebd05add4e2afce9697e126c"}
TREES = {"A": "11be4c5923dd0d0bda596d97063b140911ef77bd",
         "B": "bbedd6b56413a01ec12404201ddba5b99885cd39"}
NODES = {22: "v22.23.2", 24: "v24.21.0"}
ROWS = {"affected", "retained", "no-policy"}
PREFIX = re.compile(r"^\s*(?:(?:\[pid\s+(?P<bracket>[1-9][0-9]*)\]|(?P<plain>[1-9][0-9]*))\s+)?(?P<time>[0-9]+\.[0-9]{6})\s+(?P<body>.+)$")
ENTRY = re.compile(r"^(?P<name>[a-z][a-z0-9_]*)\(")
RESUME = re.compile(r"^<\.\.\. (?P<name>[a-z][a-z0-9_]*) resumed>(?P<tail>.*)$")
COMPLETE = re.compile(r"^(?P<name>[a-z][a-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$")
EXIT = re.compile(r"^\+\+\+ exited with (?P<code>[0-9]+) \+\+\+$")
SIGNAL = re.compile(r"^--- SIG[A-Z0-9]+(?: \{.*\})? ---$")
NOTICE = re.compile(r"^strace: Process (?P<tid>[1-9][0-9]*) (?P<action>attached|detached)$")
STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
FD = re.compile(r"^(-?[0-9]+)(?:<(.*)>)?$")
STAGE = re.compile(r"^\.fs-safe-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.tmp$")
OPEN = {"open", "openat", "openat2", "creat"}
DUP = {"dup", "dup2", "dup3"}
META = {"stat", "stat64", "lstat", "lstat64", "fstat", "fstat64", "newfstatat", "fstatat64", "statx"}
NAMED_AT = {"openat", "openat2", "newfstatat", "fstatat64", "statx", "readlinkat", "faccessat", "faccessat2", "unlinkat", "mkdirat"}
RENAME = {"rename", "renameat", "renameat2"}
SELECTED = OPEN | DUP | META | NAMED_AT | RENAME | {"readlink", "access", "close", "write", "fchmod", "fsync", "fdatasync", "fcntl", "unlink", "mkdir", "rmdir"}
FD_FIRST = {"fstat", "fstat64", "close", "write", "fchmod", "fsync", "fdatasync", "fcntl"} | DUP | NAMED_AT
TIME_FIELDS = {"st_atime", "st_mtime", "st_ctime", "st_atim", "st_mtim", "st_ctim", "st_atime_nsec", "st_mtime_nsec", "st_ctime_nsec", "stx_atime", "stx_btime", "stx_ctime", "stx_mtime"}
IDENTITY_FIELDS = {"st_dev", "st_ino", "stx_dev_major", "stx_dev_minor", "stx_ino"}


class EvidenceError(ValueError):
    pass


def require(value, message):
    if not value:
        raise EvidenceError(message)


def snapshot(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_input(path, limit, receipt):
    receipt.update(path=str(path), limitBytes=limit)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "input is not a bounded regular file")
        chunks, length = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            require(length <= limit, "input grew beyond its byte cap")
        data = b"".join(chunks)
        receipt.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        require(snapshot(before) == snapshot(os.fstat(fd)) == snapshot(os.lstat(path)), "input changed during read")
        require(len(data) == before.st_size, "incomplete input read")
        return data
    finally:
        os.close(fd)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field: " + key)
        result[key] = value
    return result


def json_value(data):
    def reject(value):
        raise EvidenceError("non-JSON number: " + value)
    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=unique_object, parse_constant=reject)


def canonical(value):
    require(isinstance(value, str) and value.startswith("/") and not value.startswith("//"), "expected absolute POSIX path")
    require(posixpath.normpath(value) == value and not value.endswith(" (deleted)"), "noncanonical or deleted path")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), "control character in pathname")
    return value


def verify_manifest(manifest, proof, role):
    require(isinstance(manifest, dict) and manifest.get("schema") == 1, "manifest schema mismatch")
    require(manifest.get("role") == role and manifest.get("row") in ROWS, "manifest role or row mismatch")
    require(type(manifest.get("nodeMajor")) is int and manifest["nodeMajor"] in NODES, "unsupported Node major")
    require(manifest.get("nodeVersion") == NODES[manifest["nodeMajor"]], "Node patch version differs from frozen protocol")
    source = manifest.get("source")
    require(isinstance(source, dict) and source.get("commit") == COMMITS[role] and source.get("dirty") is False, "source pin or cleanliness mismatch")
    require(source.get("tree") == TREES[role], "source tree differs from frozen pin")
    require(re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("nativeSha256", ""))), "native SHA256 absent or malformed")
    for name in ("rootPath", "parentPath", "targetPath", "sentinelPath"):
        canonical(manifest.get(name))
    root = manifest["rootPath"]
    require(root != "/" and manifest["parentPath"] == root + "/parent", "unexpected parent layout")
    require(manifest["targetPath"] == root + "/parent/value", "unexpected target layout")
    require(manifest["sentinelPath"] == root + "/outside-sentinel", "unexpected outside-parent sentinel layout")
    for kind in ("begin", "end"):
        require(manifest.get(kind + "Marker") == "FS_SAFE_PARENT_" + kind.upper() + " " + manifest["row"], "marker spelling mismatch")
    require(isinstance(proof, dict) and proof.get("ok") is True and proof.get("cleanup") is True, "public proof did not pass with cleanup")
    for key in ("row", "role", "nodeVersion", "nodeMajor", "source", "nativeSha256"):
        require(proof.get(key) == manifest[key], "proof binding mismatch: " + key)
    outcome = proof.get("outcome")
    require(isinstance(outcome, dict) and set(outcome) == {"bytesHex", "mode", "sentinelHex", "names"}, "public outcome fields differ from contract")
    require(outcome["bytesHex"] == b"synthetic payload".hex(), "public payload bytes mismatch")
    require(type(outcome["mode"]) is int and outcome["mode"] == 0o600, "public mode is not 0600")
    require(outcome["sentinelHex"] == b"outside sentinel retained\n".hex(), "sentinel bytes changed")
    require(outcome["names"] == ["value"], "unexpected final parent entry names")


def c_bytes(text):
    result, index = bytearray(), 0
    simple = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}
    while index < len(text):
        char = text[index]
        index += 1
        if char != "\\":
            require(ord(char) >= 32 and ord(char) != 127, "raw control character in C string")
            result.extend(char.encode("utf-8", "strict"))
        else:
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
                require(int(digits, 8) <= 255, "C escape exceeds one byte")
                result.append(int(digits, 8))
            elif char == "x":
                digits = text[index:index + 2]
                require(re.fullmatch(r"[0-9a-fA-F]{2}", digits), "invalid C hex escape")
                result.append(int(digits, 16))
                index += 2
            else:
                raise EvidenceError("unknown C escape: \\" + char)
    return bytes(result)


def quoted(text):
    match = STRING.fullmatch(text)
    require(match is not None, "missing or abbreviated quoted string: " + text)
    return c_bytes(match.group(1))


def split_args(text):
    parts, stack, start, index, in_string = [], [], 0, 0, False
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            in_string = not in_string
        elif not in_string:
            if char in "([{<":
                stack.append(char)
            elif char in ")]}>":
                if char == ">" and index and text[index - 1] == "-":
                    index += 1
                    continue
                require(stack and stack.pop() == pairs[char], "unbalanced syscall field")
            elif char == "," and not stack:
                parts.append(text[start:index].strip())
                start = index + 1
        index += 1
    require(not stack and not in_string, "incomplete syscall arguments")
    parts.append(text[start:].strip())
    require(all(parts), "empty syscall argument")
    return parts


def fd_value(text):
    cwd = re.fullmatch(r"AT_FDCWD(?:<(.*)>)?", text)
    if cwd:
        return None, c_bytes(cwd[1]).decode("utf-8", "strict") if cwd[1] is not None else None
    match = FD.fullmatch(text)
    require(match is not None, "unrecognized descriptor argument: " + text)
    annotation = c_bytes(match.group(2)).decode("utf-8", "strict") if match.group(2) is not None else None
    return int(match.group(1)), annotation


def syscall_result(text):
    match = re.fullmatch(r"(-?(?:0x[0-9a-fA-F]+|[0-9]+))(?:<(.*)>)?(?:(?: (E[A-Z0-9_]+) \(([^\n]*)\))|( \(flags [A-Z0-9_|]+\)))?", text)
    require(match is not None, "unsupported syscall result: " + text)
    value = int(match.group(1), 16 if "0x" in match.group(1) else 10)
    require((value == -1) == (match.group(3) is not None), "errno/result disagreement")
    return {"value": value, "annotation": c_bytes(match.group(2)).decode("utf-8", "strict") if match.group(2) is not None else None,
            "errno": match.group(3), "explanation": match.group(4), "decodedFlags": match.group(5)}


def parse_trace(data):
    require(data and data.endswith(b"\n") and b"\x00" not in data, "empty or truncated trace")
    pending, records, exits, tids, times = {}, [], {}, set(), {}
    for number, line in enumerate(data.decode("utf-8", "strict").splitlines(), 1):
        notice = NOTICE.fullmatch(line)
        if notice:
            require(notice["action"] == "attached", "traced task detached")
            tids.add(notice["tid"])
            continue
        prefix = PREFIX.fullmatch(line)
        require(prefix is not None, f"unrecognized trace prefix at line {number}")
        tid, timestamp, body = prefix["bracket"] or prefix["plain"] or "main", prefix["time"], prefix["body"]
        require(tid not in exits, f"record after TID {tid} exited")
        stamp = int(timestamp.replace(".", ""))
        require(stamp >= times.get(tid, 0), "per-TID timestamp moved backwards")
        times[tid] = stamp
        tids.add(tid)
        ending = EXIT.fullmatch(body)
        if ending:
            require(ending["code"] == "0" and tid not in pending, "nonzero exit or unfinished syscall at exit")
            exits[tid] = number
            continue
        if SIGNAL.fullmatch(body):
            continue
        resumed = RESUME.fullmatch(body)
        if resumed:
            require(tid in pending and pending[tid]["syscall"] == resumed["name"], "orphan or mismatched resumed syscall")
            call = pending.pop(tid)
            call["raw"] += resumed["tail"]
            call.update(endLine=number, endTimestamp=timestamp)
        else:
            entry = ENTRY.match(body)
            require(entry is not None and tid not in pending, f"unsupported or overlapping record at line {number}")
            unfinished = body.endswith("<unfinished ...>")
            call = {"tid": tid, "syscall": entry["name"], "startLine": number, "startTimestamp": timestamp,
                    "endLine": None, "endTimestamp": None, "unfinished": unfinished,
                    "raw": body[:-len("<unfinished ...>")].rstrip() if unfinished else body}
            records.append(call)
            if unfinished:
                pending[tid] = call
                continue
            call.update(endLine=number, endTimestamp=timestamp)
        complete = COMPLETE.fullmatch(call["raw"])
        require(complete is not None and complete["name"] == call["syscall"], "malformed completed syscall")
        call["arguments"] = split_args(complete["args"])
        call["resultRaw"] = complete["result"]
    require(not pending and tids == set(exits), "incomplete trace or missing terminal task records")
    return records, {"lines": len(data.splitlines()), "tids": sorted(tids), "exits": exits, "syscalls": len(records)}


def marker_span(records, manifest):
    markers = {"begin": [], "end": []}
    for call in records:
        if call["syscall"] != "write" or len(call["arguments"]) != 3:
            continue
        args = call["arguments"]
        fd, annotation = fd_value(args[0])
        if fd != 2:
            continue
        if not args[1].startswith('"'):
            continue
        # An abbreviated ordinary buffer is irrelevant unless it contains a marker.
        if not any(manifest[kind + "Marker"] in args[1] for kind in markers):
            continue
        payload = quoted(args[1])
        for kind in markers:
            expected = (manifest[kind + "Marker"] + "\n").encode("ascii")
            if manifest[kind + "Marker"].encode("ascii") in payload:
                require(fd == 2 and annotation is not None and payload == expected, "malformed fd2 marker")
                require(args[2] == str(len(expected)) and call["resultRaw"] == str(len(expected)), "short or failed marker write")
                call["marker"] = kind
                call["markerAnnotation"] = annotation
                markers[kind].append(call)
    require(all(len(value) == 1 for value in markers.values()), "expected one successful BEGIN and END marker")
    begin, end = markers["begin"][0], markers["end"][0]
    require(begin["tid"] == end["tid"] and begin["markerAnnotation"] == end["markerAnnotation"], "marker writer changed")
    require(begin["endLine"] < end["startLine"], "markers overlap or are reversed")
    inside = []
    for call in records:
        if call in (begin, end):
            continue
        overlap = any(call["startLine"] <= marker["endLine"] and call["endLine"] >= marker["startLine"] for marker in (begin, end))
        require(not overlap, "syscall overlaps a marker boundary")
        if begin["endLine"] < call["startLine"] and call["endLine"] < end["startLine"]:
            require(call["syscall"] in SELECTED, "unexpected syscall inside public call: " + call["syscall"])
            inside.append(call)
    require(inside, "no selected syscalls")
    return begin, end, inside


def fd_positions(call):
    name, args = call["syscall"], call["arguments"]
    positions = [0] if name in FD_FIRST else []
    if name in ("renameat", "renameat2"):
        positions = [0, 2]
    if name in ("dup2", "dup3"):
        positions.append(1)
    return positions


def annotate_lifetimes(records, begin, end):
    """The traced Node threads share one fd table. Reject close/reuse overlap."""
    active, lifetimes, open_calls = {}, [], {}
    events = []
    for call in records:
        events.extend(((call["startLine"], 0, call), (call["endLine"], 1, call)))
    for _, phase, call in sorted(events, key=lambda event: (event[0], event[1])):
        name, args = call["syscall"], call["arguments"]
        relevant = begin["endLine"] < call["startLine"] < end["startLine"]
        if phase == 0:
            call["markerProcess"] = begin["tid"]
            call["fdRefs"] = {}
            call["procFdRefs"] = {}
            if (name == "fcntl" and len(args) >= 2 and args[1] in ("F_GETFD", "F_SETFD")
                    and call["startLine"] == call["endLine"] < begin["startLine"]):
                number, annotation = fd_value(args[0])
                result = syscall_result(call["resultRaw"])
                if (number not in active and annotation is None
                        and result["value"] == -1 and result["errno"] == "EBADF"):
                    # A completed startup probe of a closed fd creates no owner.
                    call["closedStartupFdProbe"] = True
                    continue
            for index in fd_positions(call):
                number, annotation = fd_value(args[index])
                if number is None:
                    continue
                if name in ("dup2", "dup3") and index == 1 and number not in active:
                    continue
                if number not in active:
                    # eventfd/pipe creation is outside the selected trace filter.
                    require(not relevant or annotation is not None, "untracked descriptor without annotation")
                    life = {"id": len(lifetimes), "fd": number, "origin": "inherited-or-untraced", "openLine": None,
                            "openedPath": annotation, "path": annotation, "closeLine": None, "references": []}
                    active[number] = life
                    lifetimes.append(life)
                life = active[number]
                require(life.get("closing") is None, "descriptor used while its close is unfinished")
                if annotation is not None and life["path"] is not None:
                    require(annotation == life["path"], "descriptor annotation changed without traced publication")
                elif annotation is not None:
                    life["path"] = annotation
                    life["openedPath"] = annotation
                call["fdRefs"][index] = life["id"]
                life["references"].append(call["startLine"])
                if name == "close":
                    life["closing"] = call["startLine"]
            # /proc/self/fd path components also refer to a specific live owner.
            for arg in args:
                for match in re.finditer(r"/proc/(self|[0-9]+)/fd/([0-9]+)(?=[/\"\s]|$)", arg):
                    require(match.group(1) in ("self", str(begin["tid"])), "foreign process fd path is not an owned descriptor")
                    number = int(match.group(2))
                    require(number in active and active[number].get("closing") is None, "proc-fd path has no unambiguous live owner")
                    call["procFdRefs"][str(number)] = active[number]["id"]
            continue
        creates = name in OPEN or name in DUP or (name == "fcntl" and len(args) >= 2 and args[1] in ("F_DUPFD", "F_DUPFD_CLOEXEC"))
        if name not in SELECTED or (not relevant and not creates and name != "close" and name not in RENAME):
            continue
        result = syscall_result(call["resultRaw"])
        call["result"] = result
        if creates and result["value"] >= 0:
            number = result["value"]
            if name in ("dup2", "dup3") and number in active:
                target = active[number]
                source = call["fdRefs"].get(0)
                if source == target["id"]:
                    call["resultLife"] = target["id"]
                    continue
                require(target.get("closing") is None, "dup replacement overlaps close")
                target["closeLine"] = call["endLine"]
                target["replacedByDupLine"] = call["startLine"]
                del active[number]
            require(number not in active, "new descriptor overlaps a still-live descriptor number")
            annotation = result["annotation"]
            source = call["fdRefs"].get(0) if name not in OPEN else None
            if source is not None:
                require(annotation == lifetimes[source]["path"], "duplicate descriptor changed object path")
            life = {"id": len(lifetimes), "fd": number, "origin": name, "openLine": call["endLine"],
                    "openedPath": annotation, "path": annotation, "closeLine": None, "references": [], "duplicateOf": source}
            lifetimes.append(life)
            active[number] = life
            call["resultLife"] = life["id"]
            open_calls[life["id"]] = call
        elif name == "close":
            require(result["value"] == 0, "descriptor close failed")
            number, _ = fd_value(args[0])
            life = active.pop(number)
            require(life["id"] == call["fdRefs"][0], "descriptor close changed owner")
            life["closeLine"] = call["endLine"]
            life.pop("closing", None)
        elif name in RENAME and result["value"] == 0:
            old, new = rename_paths(call, lifetimes)
            for life in active.values():
                if life["path"] == old:
                    life["path"] = new
    return lifetimes, open_calls


def path_operand(call, index, lifetimes, dir_index=None):
    path = quoted(call["arguments"][index]).decode("utf-8", "strict")
    if path.startswith("/"):
        match = re.match(r"^/proc/(self|[0-9]+)/fd/([0-9]+)(/.*)?$", path)
        if match:
            require(match.group(1) in ("self", str(call["markerProcess"])), "decoded foreign process fd path is not owned")
            life = lifetimes[call["procFdRefs"][match.group(2)]]
            require(life["openedPath"] is not None, "proc fd has no path")
            return life["openedPath"] + (match.group(3) or "")
        return path
    require(dir_index is not None and dir_index in call["fdRefs"], "relative pathname lacks traced dirfd")
    parent = lifetimes[call["fdRefs"][dir_index]]["openedPath"]
    require(parent and parent.startswith("/"), "relative pathname dirfd is not a path")
    return parent + ("/" + path if path else "")


def rename_paths(call, lifetimes):
    if call["syscall"] == "rename":
        return path_operand(call, 0, lifetimes), path_operand(call, 1, lifetimes)
    return path_operand(call, 1, lifetimes, 0), path_operand(call, 3, lifetimes, 2)


def metadata_info(call, lifetimes):
    name, args = call["syscall"], call["arguments"]
    if name not in META:
        return None
    if name in ("fstat", "fstat64"):
        return {"kind": "descriptor", "life": call["fdRefs"][0], "path": None, "outputIndex": 1, "nofollow": False}
    if name in ("stat", "stat64", "lstat", "lstat64"):
        return {"kind": "named", "life": None, "path": path_operand(call, 0, lifetimes), "outputIndex": 1, "nofollow": name.startswith("lstat")}
    flags = args[2] if name == "statx" else args[3]
    path = quoted(args[1])
    if path == b"" and "AT_EMPTY_PATH" in flags.split("|"):
        require(0 in call["fdRefs"], "empty-path metadata lacks owned descriptor")
        return {"kind": "descriptor", "life": call["fdRefs"][0], "path": None, "outputIndex": 4 if name == "statx" else 2, "nofollow": "AT_SYMLINK_NOFOLLOW" in flags.split("|")}
    return {"kind": "named", "life": None, "path": path_operand(call, 1, lifetimes, 0), "outputIndex": 4 if name == "statx" else 2,
            "nofollow": "AT_SYMLINK_NOFOLLOW" in flags.split("|")}


def integer(text):
    require(re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", text), "noninteger metadata identity")
    return int(text, 16 if text.startswith("0x") else 10)


def metadata_fields(text):
    require(text.startswith("{") and text.endswith("}") and "..." not in text, "metadata output abbreviated; capture requires strace -v")
    fields = {}
    for part in split_args(text[1:-1]):
        match = re.fullmatch(r"([a-zA-Z_][a-zA-Z_0-9]*)=(.+)", part)
        require(match is not None and match[1] not in fields, "malformed metadata field")
        fields[match[1]] = match[2]
    if "stx_ino" in fields:
        identity = (integer(fields["stx_dev_major"]), integer(fields["stx_dev_minor"]), integer(fields["stx_ino"]))
        mode = fields.get("stx_mode", "")
    else:
        device = re.fullmatch(r"makedev\(([^,]+), ([^)]+)\)", fields.get("st_dev", ""))
        require(device is not None and "st_ino" in fields, "metadata dev/ino absent")
        identity = (integer(device[1]), integer(device[2]), integer(fields["st_ino"]))
        mode = fields.get("st_mode", "")
    require("S_IF" in mode, "metadata object type absent")
    return fields, identity, mode


def inspect_arm(data, manifest, proof, arm):
    records, arm["traceSummary"] = parse_trace(data)
    begin, end, calls = marker_span(records, manifest)
    arm["span"] = {"begin": begin, "end": end, "ordering": "start-line order; each retained call must complete before the next retained call starts"}
    arm["calls"] = calls
    lifetimes, open_calls = annotate_lifetimes(records, begin, end)
    arm["lifetimes"] = lifetimes
    stages = []
    for call in calls:
        if call["syscall"] in OPEN and call["result"]["value"] >= 0:
            life = lifetimes[call["resultLife"]]
            path = life["openedPath"]
            require(path is not None, "successful selected open lacks -yy result path")
            if path.startswith(manifest["parentPath"] + "/") and STAGE.fullmatch(posixpath.basename(path)):
                require(posixpath.dirname(path) == manifest["parentPath"] and "O_CREAT" in " ".join(call["arguments"]) and "O_EXCL" in " ".join(call["arguments"]), "stage was not exclusively created")
                stages.append(call)
    require(len(stages) == 1, "expected one unique owned stage creation")
    stage = stages[0]
    stage_life = lifetimes[stage["resultLife"]]
    stage_path = stage_life["openedPath"]
    stage_name = posixpath.basename(stage_path)
    parents = [call for call in calls if call["syscall"] == "openat2" and call["result"]["value"] >= 0
               and call["resultLife"] == stage["fdRefs"].get(0)
               and lifetimes[call["resultLife"]]["openedPath"] == manifest["parentPath"] and call["endLine"] < stage["startLine"]]
    require(len(parents) == 1, "admitted parent open is not unique before stage creation")
    parent = parents[0]
    parent_life = lifetimes[parent["resultLife"]]
    require("O_DIRECTORY" in " ".join(parent["arguments"]), "parent open is not a directory admission")
    require(parent["syscall"] == "openat2" and "RESOLVE_BENEATH" in " ".join(parent["arguments"]) and "RESOLVE_NO_MAGICLINKS" in " ".join(parent["arguments"]), "parent admission is not the required Linux beneath route")
    require(stage["syscall"] == "openat" and stage["fdRefs"].get(0) == parent_life["id"], "stage creation does not use admitted parent lifetime")
    publications = [call for call in calls if call["syscall"] in RENAME]
    require(len(publications) == 1 and publications[0]["result"]["value"] == 0, "expected one successful publication rename")
    publication = publications[0]
    require(rename_paths(publication, lifetimes) == (stage_path, manifest["targetPath"]), "publication source/target mismatch")
    require(publication["syscall"] in ("renameat", "renameat2"), "publication did not use retained directory capabilities")
    for index in (0, 2):
        owner = lifetimes[publication["fdRefs"][index]]
        while owner.get("duplicateOf") is not None:
            owner = lifetimes[owner["duplicateOf"]]
        require(owner["id"] == parent_life["id"], "publication dirfd does not descend from admitted parent lifetime")
    require(stage["endLine"] < publication["startLine"], "publication precedes stage creation")
    for life in (parent_life, stage_life):
        require(life["closeLine"] is not None and publication["endLine"] < life["closeLine"] < end["startLine"], "owned parent/stage was not closed after publication before END")
    arm["admission"] = {"parentLife": parent_life["id"], "parentOpenLine": parent["startLine"], "stageLife": stage_life["id"],
                        "stageCreateLine": stage["startLine"], "stageName": stage_name, "publicationLine": publication["startLine"],
                        "parentCloseLine": parent_life["closeLine"], "stageCloseLine": stage_life["closeLine"]}
    life_tokens, identity_tokens, excluded = {}, {}, []
    normalized, meta_events = [], []
    observed_process = False

    def life_token(life_id):
        if life_id not in life_tokens:
            life_tokens[life_id] = "fd-life-" + str(len(life_tokens) + 1)
        return life_tokens[life_id]

    def normalize_path(path, call):
        # Substitutions apply to exact rooted paths and the one evidenced stage.
        proc_fd = re.match(r"^/proc/(self|[0-9]+)/fd/([0-9]+)(?=/|$)", path)
        if proc_fd:
            require(proc_fd.group(1) in ("self", str(begin["tid"])), "decoded foreign process fd path cannot be normalized")
            require(proc_fd.group(2) in call.get("procFdRefs", {}), "decoded proc-fd path lacks an unambiguous live owner")
            if proc_fd.group(1) != "self":
                require(observed_process, "numeric proc-fd alias lacks a validated proc-self observation")
        for number, life_id in call.get("procFdRefs", {}).items():
            path = re.sub(r"^/proc/(?:self|" + re.escape(str(begin["tid"])) + r")/fd/" + re.escape(number) + r"(?=/|$)", "/proc/self/fd/" + life_token(life_id), path)
        process_root = "/proc/" + str(begin["tid"])
        if path == process_root or path.startswith(process_root + "/"):
            require(observed_process, "numeric process alias lacks a validated proc-self observation")
            path = "/proc/$PROCESS" + path[len(process_root):]
        root = manifest["rootPath"]
        if path == root or path.startswith(root + "/"):
            path = "$ROOT" + path[len(root):]
        if path == stage_name:
            return "$STAGE"
        if path.endswith("/" + stage_name):
            base = path[:-len(stage_name)]
            require(base == "$ROOT/parent/" or re.fullmatch(r"/proc/self/fd/fd-life-[0-9]+/", base), "stage spelling occurs outside its owned parent")
            return base + "$STAGE"
        return path

    for call in calls:
        name, args = call["syscall"], call["arguments"]
        if name == "write":
            path = lifetimes[call["fdRefs"][0]]["openedPath"]
            if path == "anon_inode:[eventfd]":
                require(len(args) == 3 and quoted(args[1]) == b"\x01\x00\x00\x00\x00\x00\x00\x00" and args[2] == "8" and call["result"]["value"] == 8, "unexpected runtime eventfd write")
                excluded.append({"line": call["startLine"], "reason": "libuv eventfd wakeup; not a filesystem observation", "raw": call["raw"]})
                call["excluded"] = True
                continue
            require(call["fdRefs"][0] == stage_life["id"], "unexpected non-stage write in bracket")
            require(quoted(args[1]) == b"synthetic payload" and args[2] == str(len(b"synthetic payload")) and call["result"]["value"] == len(b"synthetic payload"), "unexpected stage write")
        meta = metadata_info(call, lifetimes)
        call["metadata"] = meta
        readlink_output = 1 if name == "readlink" else 2 if name == "readlinkat" else None
        self_link = False
        if readlink_output is not None and call["result"]["value"] >= 0:
            link_bytes = quoted(args[readlink_output])
            require(len(link_bytes) == call["result"]["value"] < int(args[readlink_output + 1]), "readlink result is short, truncated or inconsistent")
            self_link = quoted(args[readlink_output - 1]) == b"/proc/self"
            if self_link:
                require(link_bytes == str(begin["tid"]).encode("ascii"), "proc-self link differs from the observed marker process")
                observed_process = True
        normalized_args = []
        for index, arg in enumerate(args):
            if index in call["fdRefs"]:
                _, annotation = fd_value(arg)
                normalized_args.append({"descriptor": life_token(call["fdRefs"][index]), "annotation": normalize_path(annotation, call) if annotation is not None else None})
            elif name in ("dup2", "dup3") and index == 1 and "resultLife" in call:
                normalized_args.append({"newDescriptor": life_token(call["resultLife"])})
            elif ((meta and index == meta["outputIndex"]) or index == readlink_output) and call["result"]["value"] == -1:
                require(re.fullmatch(r"0x[0-9a-fA-F]+", arg), "failed syscall has unexpected output buffer representation")
                normalized_args.append({"outputBuffer": "unwritten"})
                call.setdefault("unwrittenOutputBuffers", {})[str(index)] = arg
            elif meta and index == meta["outputIndex"] and call["result"]["value"] == 0:
                fields, identity, mode = metadata_fields(arg)
                if identity not in identity_tokens:
                    identity_tokens[identity] = "object-" + str(len(identity_tokens) + 1)
                call["metadataFields"] = fields
                meta.update(identity=list(identity), mode=mode, object=identity_tokens[identity])
                normalized_args.append({"object": identity_tokens[identity], "fields": {key: value for key, value in fields.items() if key not in IDENTITY_FIELDS | TIME_FIELDS},
                                        "identityFields": sorted(set(fields) & IDENTITY_FIELDS), "timestampFields": sorted(set(fields) & TIME_FIELDS)})
            elif arg.startswith('"'):
                raw = quoted(arg)
                if name == "write":
                    normalized_args.append({"bytesHex": raw.hex()})
                elif self_link and index == readlink_output:
                    normalized_args.append({"process": "$PROCESS"})
                else:
                    normalized_args.append({"string": normalize_path(raw.decode("utf-8", "strict"), call)})
            else:
                require(not re.search(r"0x[0-9a-f]+", arg) or (meta and index != meta["outputIndex"]) or arg.startswith("{"), "uninterpreted pointer/hex field in selected call")
                normalized_args.append(arg)
        result = dict(call["result"])
        if "resultLife" in call:
            result["value"] = life_token(call["resultLife"])
        if result["annotation"] is not None:
            result["annotation"] = normalize_path(result["annotation"], call)
        item = {"syscall": name, "arguments": normalized_args, "result": result}
        call["normalizedIndex"] = len(normalized)
        call["normalized"] = item
        normalized.append(item)
        if meta:
            meta_events.append(call)
    retained = [call for call in calls if not call.get("excluded")]
    for previous, current in zip(retained, retained[1:]):
        require(previous["endLine"] < current["startLine"], "filesystem calls overlap; sequence attribution is ambiguous")
    for life_id in life_tokens:
        life = lifetimes[life_id]
        require(life["openLine"] is not None and begin["endLine"] < life["openLine"] and life["closeLine"] is not None and life["closeLine"] < end["startLine"], "selected filesystem descriptor lifetime escapes the marked call")
    parent_fd = [call for call in meta_events if call["metadata"]["kind"] == "descriptor" and call["metadata"]["life"] == parent_life["id"]]
    parent_named = [call for call in meta_events if call["metadata"]["kind"] == "named" and call["metadata"]["path"] == manifest["parentPath"] and call["metadata"]["nofollow"]]
    require(parent_fd and parent_named, "missing captured parent descriptor identity or named nofollow fence")
    captured = parent_fd[0]
    require(parent["endLine"] < captured["startLine"] < stage["startLine"], "captured identity is not after parent open and before stage creation")
    identity = captured["metadata"].get("identity")
    require(identity is not None and "S_IFDIR" in captured["metadata"].get("mode", ""), "captured parent metadata is not a successful directory identity")
    captured_fields = captured["metadataFields"]
    captured_links = captured_fields.get("st_nlink", captured_fields.get("stx_nlink"))
    require(captured_links is not None and integer(captured_links) > 0, "captured parent link count absent or zero")
    for call in parent_fd + parent_named:
        require(call["result"]["value"] == 0 and call["metadata"].get("identity") == identity and "S_IFDIR" in call["metadata"].get("mode", ""), "parent descriptor/named identity mismatch or failed metadata")
        fields = call["metadataFields"]
        require(call["metadata"]["mode"] == captured["metadata"]["mode"] and fields.get("st_nlink", fields.get("stx_nlink")) == captured_links,
                "parent mode/type or link count changed between descriptor and named observations")
    receipt_checks = [call for call in parent_named if captured["endLine"] < call["startLine"] < stage["startLine"]]
    require(receipt_checks, "captured directory has no named receipt check before stage creation")
    final_checks = [call for call in parent_named if stage["endLine"] < call["startLine"] < publication["startLine"]]
    require(final_checks, "missing final nofollow parent fence before publication")
    arm.update(normalizedSequence=normalized, excludedRuntimeWrites=excluded,
               identityTable=[{"object": token, "devMajor": key[0], "devMinor": key[1], "ino": key[2]} for key, token in identity_tokens.items()],
               descriptorTokens={str(key): value for key, value in life_tokens.items()},
               counts={"normalizedCalls": len(normalized), "parentFdMetadata": len(parent_fd), "namedParentNofollowMetadata": len(parent_named)},
               fences={"capturedIdentityLine": captured["startLine"], "receiptCheckLine": receipt_checks[0]["startLine"], "finalNofollowFenceLine": final_checks[-1]["startLine"]})
    return {"sequence": normalized, "parentFd": parent_fd, "captured": captured, "receipt": receipt_checks[0],
            "captureNamed": receipt_checks, "final": final_checks[-1], "stage": stage}


def compare(arms, parsed, row):
    a, b = parsed["A"], parsed["B"]
    delta = len(b["parentFd"]) - len(a["parentFd"])
    expected = -1 if row == "affected" else 0
    require(delta == expected, f"parent descriptor metadata delta {delta}; expected {expected}")
    require(arms["A"]["counts"]["namedParentNofollowMetadata"] == arms["B"]["counts"]["namedParentNofollowMetadata"], "named parent nofollow fence count changed")
    if row != "affected":
        require(a["sequence"] == b["sequence"], "control normalized syscall sequence differs")
        return {"parentFdMetadataDelta": delta, "deletedAEvent": None, "otherwiseIdentical": True}
    candidates = []
    for call in a["parentFd"]:
        if not (a["captured"]["endLine"] < a["receipt"]["startLine"] <= a["receipt"]["endLine"] < call["startLine"] < call["endLine"] + 1 <= a["stage"]["startLine"]):
            continue
        require(call["endLine"] < a["final"]["startLine"], "candidate removed read follows final named fence")
        capture_fences = [fence for fence in a["captureNamed"] if call["endLine"] < fence["startLine"] < a["stage"]["startLine"]]
        if not capture_fences:
            continue
        index = call["normalizedIndex"]
        if a["sequence"][:index] + a["sequence"][index + 1:] == b["sequence"]:
            candidates.append((call, capture_fences[0]))
    require(len(candidates) == 1, "not exactly one uniquely attributable parent descriptor read deletion")
    call, capture_fence = candidates[0]
    return {"parentFdMetadataDelta": delta, "deletedAEvent": call, "otherwiseIdentical": True,
            "followingCaptureNofollowFenceLineA": capture_fence["startLine"],
            "preserved": ["initial captured parent identity", "named receipt check", "final named capture fence before stage creation", "final named nofollow parent fence before publication", "stage creation", "publication", "all descriptor lifetimes and closes"]}


def save_output(path, report):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    if len(sys.argv) != 8:
        print("usage: compare-syscalls.py TRACE_A MANIFEST_A PROOF_A TRACE_B MANIFEST_B PROOF_B OUTPUT", file=sys.stderr)
        return 2
    paths = [Path(value).absolute() for value in sys.argv[1:]]
    output = paths[-1]
    report = {"schema": 1, "ok": False, "status": "fail", "errors": [], "arms": {"A": {}, "B": {}},
              "provenance": {}, "comparison": None,
              "claim": "One untimed public call per arm; structural kernel evidence only. No latency, scheduling, JavaScript-await, or process-settlement claim.",
              "normalization": "Exact synthetic root prefix, exclusively-created UUID stage, descriptor lifetimes and TIDs. Metadata dev+ino equality classes are bijective within each arm; concrete identity/time outputs remain in evidence and are not claimed equal across fresh fixtures. All other fields, masks, flags, syscall names and return values remain exact. Valid libuv eventfd wakeups are retained separately."}
    data, parsed = {}, {}
    for role, start in (("A", 0), ("B", 3)):
        for offset, name in enumerate(("trace", "manifest", "proof")):
            key, path = role + ":" + name, paths[start + offset]
            report["provenance"][key] = {}
            try:
                require(output.resolve() != path.resolve(), "output overlaps input")
                data[key] = read_input(path, TRACE_LIMIT if name == "trace" else JSON_LIMIT, report["provenance"][key])
            except (OSError, EvidenceError) as error:
                report["errors"].append({"scope": key, "message": str(error)})
    try:
        source = Path(__file__).resolve()
        report["provenance"]["parser"] = {}
        require(output.resolve() != source, "output overlaps parser source")
        read_input(source, SOURCE_LIMIT, report["provenance"]["parser"])
    except (OSError, EvidenceError) as error:
        report["errors"].append({"scope": "parser", "message": str(error)})
    for role in ("A", "B"):
        arm = report["arms"][role]
        try:
            require(all(role + ":" + key in data for key in ("trace", "manifest", "proof")), "missing readable evidence input")
            manifest, proof = json_value(data[role + ":manifest"]), json_value(data[role + ":proof"])
            arm.update(manifest=manifest, publicProof=proof)
            verify_manifest(manifest, proof, role)
            parsed[role] = inspect_arm(data[role + ":trace"], manifest, proof, arm)
        except (EvidenceError, ValueError, TypeError, KeyError, IndexError, UnicodeError) as error:
            report["errors"].append({"scope": role, "message": str(error)})
    if len(parsed) == 2:
        try:
            left, right = (report["arms"][role] for role in ("A", "B"))
            for key in ("row", "nodeVersion", "nodeMajor", "nativeSha256"):
                require(left["manifest"][key] == right["manifest"][key], "paired binding differs: " + key)
            require(left["manifest"]["rootPath"] != right["manifest"]["rootPath"], "A/B roots are not distinct")
            require(len(left["manifest"]["rootPath"].encode("utf-8")) == len(right["manifest"]["rootPath"].encode("utf-8")),
                    "A/B root byte lengths differ; readlink return lengths must stay comparable")
            require(left["publicProof"]["outcome"] == right["publicProof"]["outcome"], "public outcomes differ")
            report["comparison"] = compare(report["arms"], parsed, left["manifest"]["row"])
        except (EvidenceError, ValueError, TypeError, KeyError) as error:
            report["errors"].append({"scope": "pair", "message": str(error)})
    report["ok"] = not report["errors"] and report["comparison"] is not None
    report["status"] = "pass" if report["ok"] else "fail"
    try:
        save_output(output, report)
    except (OSError, ValueError) as error:
        print(json.dumps({"ok": False, "errors": report["errors"] + [{"scope": "output", "message": str(error)}]}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({"schema": 1, "ok": report["ok"], "output": str(output), "errors": report["errors"]}, sort_keys=True), flush=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
