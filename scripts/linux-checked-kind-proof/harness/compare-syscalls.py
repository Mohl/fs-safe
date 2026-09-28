#!/usr/bin/env python3
"""Compare one frozen A/B public-call trace pair; never run a workload.

Usage: compare-syscalls.py TRACE_A MANIFEST_A PROOF_A TRACE_B MANIFEST_B PROOF_B OUTPUT
Capture: strace -f -ttt -yy -v -e abbrev=execve,execveat -s1024 -e trace=%file,fstat,fstatfs,prctl,seccomp,close,write,fchmod,fsync,fdatasync,dup,dup2,dup3,fcntl
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
PAYLOAD = bytes((index * 17 + 3) % 251 for index in range(128))
EXPECTED_ROWS = [
    ("enosys-depth1", "ENOSYS", 1, False, -1),
    ("enosys-depth8", "ENOSYS", 8, False, -8),
    ("enosys-alias", "ENOSYS", 1, True, -2),
    ("enosys-root", "ENOSYS", 0, False, 0),
    ("eperm-depth1", "EPERM", 1, False, -1),
    ("eperm-depth8", "EPERM", 8, False, -8),
    ("eperm-alias", "EPERM", 1, True, -2),
    ("kernel-depth8", "openat2", 8, False, 0),
]
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
SELECTED = OPEN | DUP | META | NAMED_AT | RENAME | {"readlink", "access", "close", "write", "fchmod", "fsync", "fdatasync", "fcntl", "unlink", "mkdir", "rmdir", "fstatfs"}
FD_FIRST = {"fstat", "fstat64", "fstatfs", "close", "write", "fchmod", "fsync", "fdatasync", "fcntl"} | DUP | NAMED_AT
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


def verify_protocol(pins, protocol):
    require(pins.get("ready") is True and protocol.get("ready") is True, "packet source pins/protocol are not ready")
    for role in ("A", "B"):
        require(set(pins[role]) == {"commit", "tree"}, "unexpected source-pin fields")
        require(all(re.fullmatch(r"[0-9a-f]{40}", str(pins[role][key])) for key in ("commit", "tree")), "source pin missing or malformed")
    require(pins["A"] != pins["B"], "source arms are identical")
    require(protocol["sourcePins"] == {role: pins[role] for role in ("A", "B")}, "protocol/source pins differ")
    require(protocol["nodeVersions"] == {"22": "v22.23.2", "24": "v24.21.0"}, "Node patch versions differ from recipe")
    rows = protocol["rows"]
    require(isinstance(rows, list) and len(rows) == len(EXPECTED_ROWS), "wrong syscall row count")
    descriptors = {row["id"]: row for row in rows}
    require(len(descriptors) == len(rows), "duplicate protocol row")
    for ident, mechanism, depth, alias, delta in EXPECTED_ROWS:
        row = descriptors.get(ident)
        require(row == {"id": ident, "mechanism": mechanism, "depth": depth, "alias": alias,
                        "expectedComponentFstatDelta": delta}, "row descriptor differs from frozen recipe: " + ident)
    require(protocol["syscalls"]["rows"] == [row[0] for row in EXPECTED_ROWS], "syscall row set/order differs")
    require(protocol["syscalls"]["nodeMajors"] == [22, 24] and protocol["syscalls"]["calls"] == 32, "syscall Node majors/call count differ")
    require(protocol["platform"] == "linux" and protocol["arch"] == "x64" and protocol["libc"] == "glibc", "unsupported syscall proof platform")
    return descriptors


def verify_manifest(manifest, proof, role, pins, protocol, expected):
    rows = {row["id"]: row for row in protocol["rows"]}
    require(isinstance(manifest, dict) and manifest.get("schema") == 1, "manifest schema mismatch")
    require(manifest.get("role") == role and manifest.get("row") in rows, "manifest role or row mismatch")
    row = rows[manifest["row"]]
    require(manifest.get("descriptor") == row and manifest.get("mechanism") == row["mechanism"], "manifest row descriptor/mechanism mismatch")
    require(type(manifest.get("nodeMajor")) is int and manifest["nodeMajor"] in (22, 24), "unsupported Node major")
    require(manifest.get("nodeVersion") == protocol["nodeVersions"][str(manifest["nodeMajor"])], "Node patch version differs from protocol")
    source = {**pins[role], "dirty": False}
    require(manifest.get("source") == source, "source pin or cleanliness mismatch")
    require(expected.get("role") == role and expected.get("source") == source, "expected consumer role/source differs")
    require(re.fullmatch(r"[0-9a-f]{64}", str(expected.get("nativeSha256", ""))), "consumer native SHA256 malformed")
    require(manifest.get("nativeSha256") == expected["nativeSha256"], "loaded native hash differs from own consumer receipt")
    require(expected.get("nativePackage") == "@openclaw/fs-safe-linux-x64-gnu", "unexpected installed native target")
    require(isinstance(expected.get("distFiles"), dict) and expected["distFiles"], "consumer has no dist/declaration receipts")
    require(all(re.fullmatch(r"[0-9a-f]{64}", str(digest)) for digest in expected["distFiles"].values()), "malformed dist receipt")
    for key, name in (("rootTarball", "@openclaw/fs-safe"), ("nativeTarball", expected["nativePackage"])):
        artifact = expected.get(key, {})
        require(artifact.get("name") == name and re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", "")))
                and re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", str(artifact.get("integrity", ""))), "consumer package receipt absent or malformed")
    require(expected["rootTarball"]["version"] == expected["nativeTarball"]["version"] == protocol["packageVersion"], "root/native package version differs from protocol")
    require(manifest.get("fallbackHook") == "0", "environment fallback hook is not disabled")
    for name in ("rootPath", "parentPath", "targetPath", "sentinelPath", "outsidePath", "primePath"):
        canonical(manifest.get(name))
    root, outside = manifest["rootPath"], manifest["outsidePath"]
    require(root != "/" and root != outside and posixpath.dirname(root) == posixpath.dirname(outside), "fixture outside sentinel is not a distinct sibling")
    components = ["actual"] if row["alias"] else ["d" + str(index) for index in range(row["depth"])]
    parent = root + ("/" + "/".join(components) if components else "")
    require(manifest["parentPath"] == parent and manifest["targetPath"] == parent + "/value", "unexpected parent/target layout")
    require(manifest["existingParentPaths"] == [root + "/" + "/".join(components[:index]) for index in range(1, len(components) + 1)], "unexpected existing parent set")
    require(manifest["sentinelPath"] == outside + "/sentinel" and manifest["primePath"] == root + "/prime-sentinel", "unexpected sentinel/prime layout")
    relative = "alias/value" if row["alias"] else "/".join(components + ["value"])
    require(manifest.get("relative") == relative, "unexpected public relative pathname")
    require(manifest.get("options") == {"mkdir": False, "durable": False, "mode": 0o600}, "public write options differ")
    if row["alias"]:
        require(manifest.get("aliasPath") == root + "/alias" and manifest.get("aliasTarget") == "actual", "alias layout differs")
    else:
        require("aliasPath" not in manifest and "aliasTarget" not in manifest, "non-alias row has alias evidence")
    for kind in ("begin", "end"):
        require(manifest.get(kind + "Marker") == "FS_SAFE_KIND_" + kind.upper() + " " + manifest["row"], "marker spelling mismatch")
    require(isinstance(proof, dict) and proof.get("ok") is True and proof.get("cleanup") is True and proof.get("phase") == "complete", "public proof did not pass with cleanup")
    for key, value in manifest.items():
        require(proof.get(key) == value, "proof binding mismatch: " + key)
    root_names = ["actual", "alias", "prime-sentinel"] if row["alias"] else ["d0", "prime-sentinel"] if row["depth"] else ["prime-sentinel", "value"]
    outcome = {"bytesHex": PAYLOAD.hex(), "mode": 0o600, "nlink": 1,
               "sentinelHex": b"outside sentinel retained\n".hex(),
               "names": ["value"] if components else root_names, "rootNames": root_names, "relative": relative}
    if row["alias"]:
        outcome["aliasTarget"] = "actual"
    require(proof.get("outcome") == outcome, "public outcome differs from exact fixture contract")


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


def opened_cloexec(call):
    name, args = call["syscall"], call["arguments"]
    if name == "fcntl":
        return args[1] == "F_DUPFD_CLOEXEC"
    if name == "openat2":
        flags = struct_fields(args[2]).get("flags", "")
    elif name in ("openat", "dup3"):
        flags = args[2]
    elif name == "open":
        flags = args[1]
    else:
        return False
    return "O_CLOEXEC" in flags.split("|")


def eventfd_state(annotation):
    if annotation is None:
        return None
    match = re.fullmatch(r"\{eventfd-count=(0|0x[1-9a-f][0-9a-f]{0,15}), eventfd-id=(0|[1-9][0-9]*), eventfd-semaphore=([01])\}", annotation)
    if match is None:
        return None
    return {"count": match[1], "id": match[2], "semaphore": match[3]}


def anonymous_census_target(target):
    return target in ("anon_inode:[eventpoll]", "anon_inode:[io_uring]", "anon_inode:[eventfd]") or (
        target is not None and re.fullmatch(r"pipe:\[[1-9][0-9]*\]", target) is not None)


def census_readlink(call, begin, end, observed_process):
    args = call["arguments"]
    if (call["syscall"] != "readlink" or len(args) != 3 or call["tid"] != begin["tid"]
            or call["startLine"] != call["endLine"]
            or not (call["endLine"] < begin["startLine"] or call["startLine"] > end["endLine"])):
        return None
    path = quoted(args[0]).decode("utf-8", "strict")
    match = re.fullmatch(r"/proc/(self|[1-9][0-9]*)/fd/(0|[1-9][0-9]*)", path)
    if match is None:
        return None
    require(match[1] == "self" or (match[1] == str(begin["tid"]) and observed_process), "census process alias is not evidenced")
    require(re.fullmatch(r"[1-9][0-9]*", args[2]), "census readlink buffer is not a positive integer")
    result = syscall_result(call["resultRaw"])
    require(result["annotation"] is None and result["decodedFlags"] is None, "census readlink result has unexpected annotation")
    observation = {"fd": int(match[2]), "path": path, "result": result,
                   "phase": "before" if call["endLine"] < begin["startLine"] else "after"}
    if result["value"] >= 0:
        target = quoted(args[1])
        require(len(target) == result["value"] < int(args[2]), "census readlink output is short, truncated or inconsistent")
        observation["target"] = target.decode("utf-8", "strict")
    else:
        require(re.fullmatch(r"0x[0-9a-fA-F]+", args[1]), "failed census readlink output is not an untouched buffer")
        observation["outputBuffer"] = args[1]
    return observation


def closed_enumeration_owner(number, call, begin, end, lifetimes, open_calls, close_calls, observed_process):
    life = next((entry for entry in reversed(lifetimes) if entry["fd"] == number), None)
    require(life is not None and life["id"] in close_calls, "census ENOENT lacks a successfully closed latest owner")
    opened, closed = open_calls.get(life["id"]), close_calls[life["id"]]
    require(opened is not None and opened["syscall"] == "openat" and opened["tid"] == closed["tid"] == begin["tid"],
            "census ENOENT latest owner is not a main-thread enumeration open")
    args = opened["arguments"]
    require(len(args) == 3 and "O_DIRECTORY" in args[2].split("|") and "O_RDONLY" in args[2].split("|"),
            "census ENOENT owner was not opened as a read-only directory")
    opened_path = quoted(args[1]).decode("utf-8", "strict")
    match = re.fullmatch(r"/proc/(self|[1-9][0-9]*)/fd", opened_path)
    require(match is not None and (match[1] == "self" or (match[1] == str(begin["tid"]) and observed_process)),
            "census ENOENT owner did not open this process enumeration directory")
    require(life["openedPath"] in ("/proc/self/fd", "/proc/" + str(begin["tid"]) + "/fd")
            and life["path"] == life["openedPath"], "census ENOENT owner annotation is not the unchanged enumeration directory")
    require(opened["endLine"] < closed["startLine"] and closed["endLine"] == life["closeLine"] < call["startLine"],
            "census ENOENT owner was not closed before the probe")
    require((closed["endLine"] < begin["startLine"] and call["endLine"] < begin["startLine"])
            or (opened["startLine"] > end["endLine"] and call["startLine"] > end["endLine"]),
            "census ENOENT owner crosses the selected span")
    return {"life": life["id"], "openLine": opened["startLine"], "closeLine": closed["endLine"]}


def annotate_lifetimes(records, begin, end):
    """The traced Node threads share one fd table. Reject close/reuse overlap."""
    active, lifetimes, open_calls = {}, [], {}
    census_observations, close_calls, observed_process = {}, {}, False
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
            census = census_readlink(call, begin, end, observed_process)
            if census is not None:
                number, result = census["fd"], census["result"]
                if result["value"] < 0:
                    require(number not in active, "failed census readlink contradicts a live descriptor owner")
                if number in census_observations:
                    require(census.get("target") == census_observations[number]["target"], "anonymous census target changed without traced close")
                if number not in active:
                    if result["value"] >= 0:
                        require(anonymous_census_target(census["target"]), "untracked census target is not a recognized anonymous resource")
                        census["kind"] = "anonymous-resource"
                        census_observations.setdefault(number, {"target": census["target"], "line": call["startLine"]})
                    else:
                        require(result["value"] == -1 and result["errno"] == "ENOENT" and number not in census_observations,
                                "untracked census failure is not a closed enumeration-directory probe")
                        census["kind"] = "closed-enumeration-directory"
                        census["retiredOwner"] = closed_enumeration_owner(number, call, begin, end, lifetimes, open_calls, close_calls, observed_process)
                    call["fdCensus"] = census
                    call["result"] = result
                    continue
            if (name == "fcntl" and len(args) >= 2 and args[1] in ("F_GETFD", "F_SETFD")
                    and call["startLine"] == call["endLine"] < begin["startLine"]):
                number, annotation = fd_value(args[0])
                result = syscall_result(call["resultRaw"])
                if (number not in active and number not in census_observations and annotation is None
                        and result["value"] == -1 and result["errno"] == "EBADF"):
                    # A completed startup probe of a closed fd creates no owner.
                    call["closedStartupFdProbe"] = True
                    continue
            for index in fd_positions(call):
                number, annotation = fd_value(args[index])
                if number is None:
                    continue
                if number in census_observations:
                    require(not (name in ("dup2", "dup3") and index == 1), "dup replacement of an anonymous census observation is not modeled")
                    target = "anon_inode:[eventfd]" if eventfd_state(annotation) is not None else annotation
                    require(target == census_observations[number]["target"], "descriptor annotation differs from its anonymous census observation")
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
                eventfd = eventfd_state(annotation)
                if annotation is not None and life["path"] is not None:
                    previous_eventfd = eventfd_state(life["path"])
                    if eventfd is not None and previous_eventfd is not None:
                        # The wakeup count changes; eventfd identity and mode must not.
                        require(eventfd["id"] == previous_eventfd["id"] and eventfd["semaphore"] == previous_eventfd["semaphore"],
                                "descriptor annotation changed without traced publication")
                    else:
                        require(annotation == life["path"], "descriptor annotation changed without traced publication")
                elif annotation is not None:
                    life["path"] = annotation
                    life["openedPath"] = annotation
                if eventfd is not None:
                    life.setdefault("eventfdObservations", []).append({"line": call["startLine"], "annotation": annotation, **eventfd})
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
        if name == "readlink" and len(args) == 3 and quoted(args[0]) == b"/proc/self":
            result = syscall_result(call["resultRaw"])
            if result["value"] >= 0:
                target = quoted(args[1])
                require(re.fullmatch(r"[1-9][0-9]*", args[2]) and len(target) == result["value"] < int(args[2])
                        and target == str(begin["tid"]).encode("ascii"), "proc-self observation does not evidence the marker process")
                observed_process = True
        if name in ("execve", "execveat") and syscall_result(call["resultRaw"])["value"] == 0:
            for number, life in list(active.items()):
                if life.get("cloexec") is True:
                    require(life.get("closing") is None, "exec-time descriptor retirement overlaps close")
                    life["closeLine"] = call["endLine"]
                    life["closedByExecLine"] = call["startLine"]
                    del active[number]
            continue
        if name == "fcntl" and len(args) >= 3 and args[1] == "F_SETFD" and syscall_result(call["resultRaw"])["value"] == 0:
            life = lifetimes[call["fdRefs"][0]]
            require(args[2] in ("0", "FD_CLOEXEC"), "unknown descriptor flags")
            life["cloexec"] = args[2] == "FD_CLOEXEC"
        creates = name in OPEN or name in DUP or (name == "fcntl" and len(args) >= 2 and args[1] in ("F_DUPFD", "F_DUPFD_CLOEXEC"))
        if name not in SELECTED or (not relevant and not creates and name != "close" and name not in RENAME):
            continue
        result = syscall_result(call["resultRaw"])
        call["result"] = result
        if creates and result["value"] >= 0:
            number = result["value"]
            require(number not in census_observations, "new descriptor overlaps an unretired anonymous census observation")
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
                    "openedPath": annotation, "path": annotation, "closeLine": None, "references": [], "duplicateOf": source,
                    "cloexec": opened_cloexec(call)}
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
            close_calls[life["id"]] = call
            census_observations.pop(number, None)
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


def struct_fields(text):
    require(text.startswith('{') and text.endswith('}') and '...' not in text, 'abbreviated or malformed structure')
    result = {}
    for field in split_args(text[1:-1]):
        key, sep, value = field.partition('=')
        require(sep and key not in result, 'malformed or duplicate structure field')
        result[key] = value
    return result


def verify_mechanism(records, begin, manifest, launch):
    """Attest the real selection from the entire retained trace, not a label."""
    successful_execs = []
    for call in records:
        if call['syscall'] not in ('execve', 'execveat'):
            continue
        offset = 1 if call['syscall'] == 'execveat' else 0
        args = call['arguments']
        require(len(args) > offset + 2 and re.fullmatch(r'0x[0-9a-fA-F]+ /\* [0-9]+ vars \*/', args[offset + 2]),
                'exec environment is not abbreviated; do not retain environment values')
        if syscall_result(call['resultRaw'])['value'] != 0:
            continue
        require(args[offset + 1].startswith('[') and args[offset + 1].endswith(']'), 'exec argument vector missing')
        argv = [quoted(value).decode('utf-8') for value in split_args(args[offset + 1][1:-1])]
        successful_execs.append((call, quoted(args[offset]).decode('utf-8'), argv))
    node_execs = [(call, executable, argv) for call, executable, argv in successful_execs
                  if len(argv) > 1 and argv[1].endswith('/harness/syscall-probe.mjs')]
    require(len(node_execs) == 1, 'expected one traced Node syscall-probe exec')
    node_exec, executable, _ = node_execs[0]
    command = launch['command']
    node_index = 0 if manifest['mechanism'] == 'openat2' else 2
    require(executable == command[node_index] and node_execs[0][2] == command[node_index:], 'traced Node executable/argv differs from launcher receipt')
    require(manifest['launch'] == {'executable': launch['runtime']['path'], 'argv': command[node_index + 1:]}, 'public proof launch binding differs from launcher receipt')
    require([call for call, _, _ in successful_execs if node_exec['startLine'] <= call['startLine'] < begin['startLine']] == [node_exec], 'unexpected later exec before selected call')
    native_opens = [call for call in records if node_exec['endLine'] < call['startLine'] < begin['startLine'] and call['syscall'] in OPEN
                    and syscall_result(call['resultRaw'])['value'] >= 0 and (syscall_result(call['resultRaw'])['annotation'] or '').endswith('.node')]
    require(native_opens and all(syscall_result(call['resultRaw'])['annotation'] == manifest['nativePath'] for call in native_opens), 'observed native-addon open differs from installed consumer path')
    require(posixpath.basename(executable) == 'node' and node_exec['tid'] == begin['tid']
            and node_exec['endLine'] < begin['startLine'], 'probe is not the marker process Node execution')
    openat2 = [call for call in records if call['syscall'] == 'openat2']
    probes = []
    for call in openat2:
        args = call['arguments']
        if len(args) != 4 or fd_value(args[0])[0] is not None or quoted(args[1]) != b'.':
            continue
        fields = struct_fields(args[2])
        flags = set(fields.get('flags', '').split('|'))
        if {'O_PATH', 'O_DIRECTORY', 'O_CLOEXEC'} <= flags:
            require(flags <= {'O_RDONLY', 'O_PATH', 'O_DIRECTORY', 'O_CLOEXEC'}
                    and fields.get('mode', '0') == '0'
                    and set(fields.get('resolve', '').split('|')) == {'RESOLVE_BENEATH', 'RESOLVE_NO_MAGICLINKS'}
                    and args[3] == '24', 'harmless capability probe flags differ')
            probes.append(call)
    require(len(probes) == 1 and probes[0] is openat2[0], 'missing, repeated, or late harmless capability probe')
    probe = probes[0]
    require(node_exec['endLine'] < probe['startLine'] < probe['endLine'] + 1 <= begin['startLine'], 'capability probe is not before selected call after Node exec')
    mechanism = manifest['mechanism']
    result = syscall_result(probe['resultRaw'])
    nnp = [call for call in records if call['syscall'] == 'prctl' and call['arguments'][0] == 'PR_SET_NO_NEW_PRIVS']
    filters = [call for call in records if (call['syscall'] == 'prctl' and call['arguments'][0] == 'PR_SET_SECCOMP') or call['syscall'] == 'seccomp']
    if mechanism == 'openat2':
        require(result['value'] >= 0 and result['errno'] is None, 'control did not use a real successful openat2 probe')
        require(not nnp and not filters, 'ordinary-native control installed a seccomp policy')
        require(all(syscall_result(call['resultRaw'])['errno'] not in ('ENOSYS', 'EPERM') for call in openat2), 'control contains unavailable openat2 calls')
        return {'mechanism': mechanism, 'nodeExec': node_exec, 'probe': probe, 'hook': manifest['fallbackHook']}
    require(result['value'] == -1 and result['errno'] == mechanism, 'harmless probe errno does not match requested denial')
    require(len(openat2) == 1, 'denied mechanism made unexpected further openat2 calls after cached admission')
    require(len(nnp) == len(filters) == 1, 'expected exactly one no-new-privileges and one seccomp-filter installation')
    nnp, installed = nnp[0], filters[0]
    require(nnp['arguments'] == ['PR_SET_NO_NEW_PRIVS', '1', '0', '0', '0'] and syscall_result(nnp['resultRaw'])['value'] == 0, 'no-new-privileges installation failed or differs')
    require(installed['syscall'] == 'prctl' and installed['arguments'][:2] == ['PR_SET_SECCOMP', 'SECCOMP_MODE_FILTER']
            and len(installed['arguments']) == 3 and syscall_result(installed['resultRaw'])['value'] == 0, 'seccomp-filter installation failed or differs')
    require(struct_fields(installed['arguments'][2]).get('len') == '4', 'denial filter program length differs')
    wrappers = [(call, exe, argv) for call, exe, argv in successful_execs
                if call['endLine'] < nnp['startLine'] and len(argv) > 3 and argv[1] == mechanism
                and any(value.endswith('/harness/syscall-probe.mjs') for value in argv[3:])]
    require(len(wrappers) == 1, 'missing unique denial-wrapper exec')
    wrapper, wrapper_executable, wrapper_argv = wrappers[0]
    require(wrapper_executable == command[0] == launch['denialWrapper']['buildReceipt']['binaryPath']
            and wrapper_argv == command, 'traced denial-wrapper path/argv differs from recorded build and launch')
    require(wrapper['tid'] == nnp['tid'] == installed['tid'] == node_exec['tid'] == begin['tid'], 'filter installation process does not exec the selected Node process')
    require(wrapper['endLine'] < nnp['startLine'] <= nnp['endLine'] < installed['startLine']
            <= installed['endLine'] < node_exec['startLine'], 'seccomp filter was not installed before Node exec')
    require([call for call, _, _ in successful_execs if wrapper['startLine'] <= call['startLine'] <= begin['startLine']] == [wrapper, node_exec],
            'unexpected exec between wrapper and selected call')
    return {'mechanism': mechanism, 'wrapperExec': wrapper, 'noNewPrivileges': nnp, 'filter': installed,
            'nodeExec': node_exec, 'probe': probe, 'hook': manifest['fallbackHook']}


def checked_components(calls, lifetimes, stage, manifest):
    """Only a probe's initial verify-entry pair may own a deleted type sample."""
    row = manifest['descriptor']
    expected_paths = ([manifest['aliasPath'], manifest['parentPath']] if row['alias'] else manifest['existingParentPaths']) if row['mechanism'] != 'openat2' else []
    probes = []
    for call in calls:
        if call['syscall'] != 'openat' or call['result']['value'] < 0:
            continue
        flags = set(call['arguments'][2].split('|'))
        if 'O_PATH' not in flags or 'O_NOFOLLOW' not in flags or 'O_DIRECTORY' in flags:
            continue
        require(flags <= {'O_RDONLY', 'O_PATH', 'O_CLOEXEC', 'O_NOFOLLOW', 'O_LARGEFILE'} and 'O_CLOEXEC' in flags, 'unexpected component probe flags')
        life = lifetimes[call['resultLife']]
        probes.append((call, life))
    require([life['openedPath'] for _, life in probes] == expected_paths, 'component probe lifetime/path sequence differs from row contract')
    summaries, deletions = [], []
    for opened, life in probes:
        index = opened['normalizedIndex']
        require(index + 2 < len(calls), 'component initial verify-entry is incomplete')
        named, sampled = calls[index + 1:index + 3]
        require(named.get('metadata', {}).get('kind') == 'named' and named['metadata']['nofollow']
                and named['metadata']['path'] == life['openedPath'] and named['result']['value'] == 0, 'component open not immediately followed by its fresh named nofollow observation')
        require(sampled.get('metadata', {}).get('kind') == 'descriptor' and sampled['metadata']['life'] == life['id']
                and sampled['result']['value'] == 0, 'component named observation not immediately followed by owned descriptor sample')
        for event in (named, sampled):
            require(event['metadata'].get('identity') is not None, 'component initial identity absent')
        require(named['metadata']['identity'] == sampled['metadata']['identity'] and named['metadata']['mode'] == sampled['metadata']['mode'], 'component initial pathname/descriptor identity or type differs')
        expected_type = 'S_IFLNK' if row['alias'] and life['openedPath'] == manifest['aliasPath'] else 'S_IFDIR'
        require(expected_type in sampled['metadata']['mode'], 'component type differs from fixture')
        fd_events = [call for call in calls if call.get('metadata', {}).get('kind') == 'descriptor' and call['metadata']['life'] == life['id']]
        named_events = [call for call in calls if call.get('metadata', {}).get('kind') == 'named' and call['metadata']['path'] == life['openedPath'] and call['metadata']['nofollow']]
        require(len(fd_events) >= 2 and len(named_events) >= 2, 'component lacks retained later descriptor/pathname fences')
        for event in fd_events + named_events:
            require(event['result']['value'] == 0 and event['metadata'].get('identity') == sampled['metadata']['identity']
                    and event['metadata'].get('mode') == sampled['metadata']['mode'], 'component fresh fences disagree on identity/mode')
        require(life['closeLine'] is not None and sampled['endLine'] < life['closeLine'] < stage['startLine'], 'component owner was not closed after checks before staging')
        duplicate = calls[index + 3] if index + 3 < len(calls) else None
        has_duplicate = bool(duplicate and duplicate.get('metadata', {}).get('kind') == 'descriptor' and duplicate['metadata']['life'] == life['id'])
        if manifest['role'] == 'A':
            require(has_duplicate and duplicate['normalized'] == sampled['normalized'], 'baseline missing exact second immediately adjacent type-only descriptor sample')
            deletions.append(duplicate)
        else:
            require(not has_duplicate, 'candidate retains an immediately repeated type-only descriptor sample')
        if expected_type == 'S_IFLNK':
            fsstats = [event for event in calls if event['syscall'] == 'fstatfs' and event['fdRefs'].get(0) == life['id']]
            require(len(fsstats) >= 2 and all(event['result']['value'] == 0 for event in fsstats), 'link filesystem admission or repeated admission missing')
            child_links = [event for event in calls if event['syscall'] == 'readlinkat' and event['fdRefs'].get(0) == life['id'] and quoted(event['arguments'][1]) == b'']
            named_links = [event for event in calls if event['syscall'] == 'readlinkat' and quoted(event['arguments'][1]) == b'alias'
                           and path_operand(event, 1, lifetimes, 0) == life['openedPath']]
            require(len(child_links) == 1 and named_links, 'retained link target sample or fresh named rereads missing')
            require(all(quoted(event['arguments'][2]) == b'actual' and event['result']['value'] == 6 for event in child_links + named_links), 'link target changed or was truncated')
            for event in fsstats:
                after = calls[event['normalizedIndex'] + 1]
                require(after.get('metadata', {}).get('kind') == 'descriptor' and after['metadata']['life'] == opened['fdRefs'][0]
                        and after['result']['value'] == 0 and 'S_IFDIR' in after['metadata'].get('mode', ''), 'link mount check lacks immediate fresh parent mode admission')
        summaries.append({'path': life['openedPath'], 'life': life['id'], 'openLine': opened['startLine'],
                          'initialNamedLine': named['startLine'], 'initialDescriptorLine': sampled['startLine'],
                          'deletedTypeSampleLine': duplicate['startLine'] if manifest['role'] == 'A' else None,
                          'descriptorObservationLines': [event['startLine'] for event in fd_events],
                          'namedNofollowObservationLines': [event['startLine'] for event in named_events], 'closeLine': life['closeLine']})
    return summaries, deletions


def normalize_fixture_parent(path, manifest, launch):
    root = manifest["rootPath"]
    parent = posixpath.dirname(root)
    if path != parent:
        return path
    outside = manifest["outsidePath"]
    canonical(root)
    canonical(outside)
    require(root == parent + "/row-0" and outside == parent + "/outside-0",
            "fixture-parent normalization requires the generated row-0/outside-0 layout")
    argv, command = manifest["launch"]["argv"], launch["command"]
    node_index = 0 if manifest["mechanism"] == "openat2" else 2
    require(isinstance(argv, list) and len(argv) == 7 and isinstance(command, list) and len(command) == node_index + 8,
            "fixture-parent normalization lacks a bound probe invocation")
    base = canonical(argv[2])
    require(command[node_index + 3] == base and posixpath.dirname(parent) == base,
            "fixture parent is not directly beneath the bound private-fixture argument")
    require(re.fullmatch(r"fs-safe-checked-kind-[A-Za-z0-9]{6}", posixpath.basename(parent)),
            "fixture parent does not have the generated private-workspace name")
    return "$FIXTURE_PARENT"


def inspect_arm(data, manifest, proof, arm, launch):
    records, arm["traceSummary"] = parse_trace(data)
    begin, end, calls = marker_span(records, manifest)
    arm["mechanismEvidence"] = verify_mechanism(records, begin, manifest, launch)
    arm["span"] = {"begin": begin, "end": end, "ordering": "start-line order; each retained call must complete before the next retained call starts"}
    arm["calls"] = calls
    lifetimes, open_calls = annotate_lifetimes(records, begin, end)
    arm["lifetimes"] = lifetimes
    arm["outOfSpanFdCensus"] = [call for call in records if "fdCensus" in call]
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
    require(stage["syscall"] in ("openat", "openat2") and 0 in stage["fdRefs"], "stage creation does not use an owned parent lifetime")
    parent_life = lifetimes[stage["fdRefs"][0]]
    parent = open_calls.get(parent_life["id"])
    require(parent is not None and parent_life["openedPath"] == manifest["parentPath"] and parent["endLine"] < stage["startLine"], "missing owned parent admission before staging")
    if manifest["descriptor"]["depth"] == 0:
        require(parent["syscall"] in DUP or (parent["syscall"] == "fcntl" and parent["arguments"][1] in ("F_DUPFD", "F_DUPFD_CLOEXEC")), "root-level empty parent did not duplicate its owned descriptor")
    elif manifest["mechanism"] == "openat2":
        require(parent["syscall"] == "openat2" and all(flag in " ".join(parent["arguments"]) for flag in ("O_DIRECTORY", "RESOLVE_BENEATH", "RESOLVE_NO_MAGICLINKS")), "control parent did not use real beneath openat2")
    else:
        require(parent["syscall"] == "openat" and all(flag in parent["arguments"][2].split("|") for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")), "fallback parent admission flags differ")
    publications = [call for call in calls if call["syscall"] in RENAME]
    require(len(publications) == 1 and publications[0]["result"]["value"] == 0, "expected one successful publication rename")
    publication = publications[0]
    require(rename_paths(publication, lifetimes) == (stage_path, manifest["targetPath"]), "publication source/target mismatch")
    require(publication["syscall"] in ("renameat", "renameat2"), "publication did not use retained directory capabilities")
    for index in (0, 2):
        owner = lifetimes[publication["fdRefs"][index]]
        while owner.get("duplicateOf") is not None:
            owner = lifetimes[owner["duplicateOf"]]
        admitted = parent_life
        while admitted.get("duplicateOf") is not None:
            admitted = lifetimes[admitted["duplicateOf"]]
        require(owner["id"] == admitted["id"], "publication dirfd does not descend from admitted parent capability")
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
        path = normalize_fixture_parent(path, manifest, launch)
        if path == "$FIXTURE_PARENT":
            arm["fixtureParentNormalization"] = {"path": posixpath.dirname(manifest["rootPath"]),
                                                 "baseArgument": manifest["launch"]["argv"][2], "token": path}
        root = manifest["rootPath"]
        if path == root or path.startswith(root + "/"):
            path = "$ROOT" + path[len(root):]
        if path == stage_name:
            return "$STAGE"
        if path.endswith("/" + stage_name):
            base = path[:-len(stage_name)]
            require(base == "$ROOT" + manifest["parentPath"][len(root):] + "/" or re.fullmatch(r"/proc/self/fd/fd-life-[0-9]+/", base), "stage spelling occurs outside its owned parent")
            return base + "$STAGE"
        return path

    for call in calls:
        name, args = call["syscall"], call["arguments"]
        if name == "write":
            path = lifetimes[call["fdRefs"][0]]["openedPath"]
            if path == "anon_inode:[eventfd]" or eventfd_state(path) is not None:
                require(len(args) == 3 and quoted(args[1]) == b"\x01\x00\x00\x00\x00\x00\x00\x00" and args[2] == "8" and call["result"]["value"] == 8, "unexpected runtime eventfd write")
                excluded.append({"line": call["startLine"], "reason": "libuv eventfd wakeup; not a filesystem observation", "raw": call["raw"]})
                call["excluded"] = True
                continue
            require(call["fdRefs"][0] == stage_life["id"], "unexpected non-stage write in bracket")
            require(quoted(args[1]) == PAYLOAD and args[2] == str(len(PAYLOAD)) and call["result"]["value"] == len(PAYLOAD), "unexpected stage write")
        meta = metadata_info(call, lifetimes)
        call["metadata"] = meta or {}
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
            elif name == "fstatfs" and index == 1:
                require(call["result"]["value"] == 0, "retained link filesystem admission failed")
                fields = struct_fields(arg)
                require({"f_type", "f_flags", "f_fsid"} <= set(fields), "filesystem admission fields absent")
                call["filesystemFields"] = fields
                normalized_args.append({"filesystemFields": {key: ("$VOLATILE_FREE_COUNTER" if key in {"f_bfree", "f_bavail", "f_ffree"} else value) for key, value in fields.items()}})
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
    # The baseline and candidate must carry the same retained namespace and fd
    # observations; only the per-component initial repeated samples can differ.
    summaries, deletions = checked_components(retained, lifetimes, stage, manifest)
    parent_fd = [call for call in meta_events if call["metadata"]["kind"] == "descriptor" and call["metadata"]["life"] == parent_life["id"]]
    require(parent_fd and all(call["result"]["value"] == 0 and "S_IFDIR" in call["metadata"].get("mode", "") for call in parent_fd), "missing successful retained parent descriptor inspection")
    parent_identity = parent_fd[0]["metadata"]["identity"]
    require(all(call["metadata"]["identity"] == parent_identity for call in parent_fd), "retained parent descriptor changed identity")
    require(any(parent["endLine"] < call["startLine"] < stage["startLine"] for call in parent_fd), "parent descriptor was not checked before staging")
    named_nofollow = [call for call in meta_events if call["metadata"]["kind"] == "named" and call["metadata"]["nofollow"]]
    require(named_nofollow, "no retained nofollow namespace observations")
    arm.update(normalizedSequence=normalized, excludedRuntimeWrites=excluded, components=summaries,
               identityTable=[{"object": token, "devMajor": key[0], "devMinor": key[1], "ino": key[2]} for key, token in identity_tokens.items()],
               descriptorTokens={str(key): value for key, value in life_tokens.items()},
               counts={"normalizedCalls": len(normalized), "componentProbes": len(summaries),
                       "componentFdMetadata": sum(len(component["descriptorObservationLines"]) for component in summaries),
                       "namedNofollowMetadata": len(named_nofollow), "typeDispatchDuplicates": len(deletions)})
    return {"sequence": normalized, "components": summaries, "deletions": deletions}


def compare(arms, parsed, row):
    a, b = parsed["A"], parsed["B"]
    expected = row["expectedComponentFstatDelta"]
    delta = arms["B"]["counts"]["componentFdMetadata"] - arms["A"]["counts"]["componentFdMetadata"]
    require(delta == expected, f"component descriptor metadata delta {delta}; expected {expected}")
    require(len(a["deletions"]) == -expected and not b["deletions"], "component type-read deletion count differs")
    require(arms["A"]["counts"]["namedNofollowMetadata"] == arms["B"]["counts"]["namedNofollowMetadata"], "fresh nofollow namespace observation count changed")
    removed = {call["normalizedIndex"] for call in a["deletions"]}
    require(len(removed) == len(a["deletions"]), "ambiguous deletion attribution")
    require([event for index, event in enumerate(a["sequence"]) if index not in removed] == b["sequence"], "normalized sequences differ beyond the owned initial type-read deletions")
    return {"componentFstatDelta": delta, "deletedAEvents": a["deletions"], "otherwiseIdentical": True,
            "preserved": ["fresh nofollow component names", "initial verified component descriptor samples", "all subsequent walk/expected/opened descriptor checks", "link mount and parent-mode admission", "link target rereads", "staging and publication order", "all descriptor lifetimes and closes", "exact public outcome"]}


def save_output(path, report):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def verify_launch(launch, manifest, protocol, pins_digest, protocol_digest, wrapper_source_digest, trace_path, manifest_path, proof_path):
    require(launch.get("schema") == 1 and launch.get("fallbackHook") == "0", "invalid launcher receipt or enabled fallback hook")
    require(launch.get("pinsSha256") == pins_digest and launch.get("protocolSha256") == protocol_digest, "launcher source pins/protocol differ")
    require(launch.get("row") == manifest["row"] and launch.get("mechanism") == manifest["mechanism"] and launch.get("nodeMajor") == manifest["nodeMajor"], "launcher row/mechanism/Node differs")
    require(launch.get("tracePath") and posixpath.basename(canonical(launch["tracePath"])) == trace_path.name, "launcher trace filename differs")
    command = launch.get("command")
    node_index = 0 if manifest["mechanism"] == "openat2" else 2
    require(isinstance(command, list) and len(command) == node_index + 8 and all(isinstance(value, str) for value in command), "unexpected launch command shape")
    for index in (node_index, node_index + 1, node_index + 2, node_index + 3, node_index + 6, node_index + 7):
        canonical(command[index])
    require(command[node_index + 1].endswith("/harness/syscall-probe.mjs") and command[node_index + 4:node_index + 6] == [manifest["row"], str(manifest["nodeMajor"])], "launcher probe row or Node argv mismatch")
    require(posixpath.basename(command[node_index + 6]) == manifest_path.name and posixpath.basename(command[node_index + 7]) == proof_path.name, "launcher proof/manifest filenames differ from paired inputs")
    require(manifest["expectedPath"] == command[node_index + 2] + "/expected.json", "observed consumer receipt path differs from launched consumer")
    require(manifest["expectedSha256"] == manifest["expectedReceipt"]["sha256"], "observed consumer digest differs from archived receipt")
    require(canonical(manifest["nativePath"]).startswith(command[node_index + 2] + "/node_modules/") and manifest["nativePath"].endswith("/fs-safe-native.node"), "native path lies outside launched installed consumer")
    runtime = launch.get("runtime", {})
    canonical(runtime.get("path"))
    require(re.fullmatch(r"[0-9a-f]{64}", str(runtime.get("sha256", ""))), "launcher runtime hash missing")
    require(manifest["launch"] == {"executable": runtime["path"], "argv": command[node_index + 1:]}, "manifest invocation differs from launcher receipt")
    wrapper = launch.get("denialWrapper")
    if manifest["mechanism"] == "openat2":
        require(wrapper is None, "kernel control used a denial wrapper")
    else:
        require(isinstance(wrapper, dict) and re.fullmatch(r"[0-9a-f]{64}", str(wrapper.get("buildReceiptSha256", ""))), "missing denial-wrapper build receipt")
        raw_receipt = wrapper.get("buildReceiptText")
        require(isinstance(raw_receipt, str) and hashlib.sha256(raw_receipt.encode("utf-8")).hexdigest() == wrapper["buildReceiptSha256"], "denial build receipt raw digest mismatch")
        receipt = wrapper.get("buildReceipt", {})
        require(json_value(raw_receipt.encode("utf-8")) == receipt, "denial build receipt snapshot differs from raw bytes")
        require(set(receipt) == {"sourcePath", "sourceSha256", "binaryPath", "binarySha256", "compilerPath", "compilerSha256", "command", "processLabel"}, "denial-wrapper build receipt fields differ")
        require(receipt["sourceSha256"] == wrapper_source_digest and receipt["processLabel"] == "compile-deny-wrapper", "wrapper source is not the frozen harness or build owner differs")
        require(command[0] == canonical(receipt["binaryPath"]) and command[1] == manifest["mechanism"], "wrapper launch differs from compiled binary")
        for key in ("binarySha256", "compilerSha256"):
            require(re.fullmatch(r"[0-9a-f]{64}", str(receipt[key])), "wrapper binary/compiler digest malformed")
        require(receipt["command"] == [canonical(receipt["compilerPath"]), canonical(receipt["sourcePath"]), "-o", receipt["binaryPath"]], "wrapper compile command differs from frozen source recipe")


def main():
    if len(sys.argv) != 8:
        print("usage: compare-syscalls.py TRACE_A MANIFEST_A PROOF_A TRACE_B MANIFEST_B PROOF_B OUTPUT", file=sys.stderr)
        return 2
    paths = [Path(value).absolute() for value in sys.argv[1:]]
    output = paths[-1]
    report = {"schema": 1, "ok": False, "status": "fail", "errors": [], "arms": {"A": {}, "B": {}},
              "provenance": {}, "comparison": None,
              "claim": "One untimed public call per arm; structural kernel evidence only. No latency, scheduling, JavaScript-await, or process-settlement claim.",
              "normalization": "Exact synthetic root prefix, exact invocation-bound fixture parent, exclusively-created UUID stage, descriptor lifetimes and TIDs. Metadata dev+ino equality classes are bijective within each arm; concrete identity/time outputs remain in evidence and are not claimed equal across fresh fixtures. Only fstatfs free counters f_bfree/f_bavail/f_ffree are additionally normalized; raw values stay in evidence. All other fields, masks, flags, syscall names and return values remain exact. Valid libuv eventfd wakeups are retained separately."}
    data, parsed, contract = {}, {}, {}
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
    try:
        packet = Path(__file__).resolve().parent.parent
        for key in ("pins", "protocol"):
            report["provenance"][key] = {}
            contract[key] = json_value(read_input(packet / (key + ".json"), JSON_LIMIT, report["provenance"][key]))
        report["provenance"]["wrapperSource"] = {}
        read_input(packet / "harness/deny-openat2.c", SOURCE_LIMIT, report["provenance"]["wrapperSource"])
        verify_protocol(contract["pins"], contract["protocol"])
        contract["ready"] = True
    except (OSError, EvidenceError, ValueError, TypeError, KeyError, UnicodeError) as error:
        report["errors"].append({"scope": "contract", "message": str(error)})
    for role in ("A", "B"):
        arm = report["arms"][role]
        try:
            require(all(role + ":" + key in data for key in ("trace", "manifest", "proof")), "missing readable evidence input")
            manifest, proof = json_value(data[role + ":manifest"]), json_value(data[role + ":proof"])
            arm.update(manifest=manifest, publicProof=proof)
            require(contract.get("ready") is True, "source pins/protocol not validated")
            receipt = manifest.get("expectedReceipt", {})
            filename = receipt.get("file")
            require(isinstance(filename, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", filename) and filename not in (".", ".."), "expected consumer sidecar is not a strict basename")
            manifest_path = paths[1 if role == "A" else 4]
            require(filename == manifest_path.name + ".expected.json", "consumer sidecar name differs from manifest contract")
            receipt_path = manifest_path.parent / filename
            require(output.resolve() != receipt_path.resolve(), "output overlaps consumer receipt")
            report["provenance"][role + ":expected"] = {}
            receipt_data = read_input(receipt_path, SOURCE_LIMIT, report["provenance"][role + ":expected"])
            require(hashlib.sha256(receipt_data).hexdigest() == receipt.get("sha256"), "consumer sidecar digest mismatch")
            expected = json_value(receipt_data)
            arm["expectedConsumer"] = expected
            verify_manifest(manifest, proof, role, contract["pins"], contract["protocol"], expected)
            trace_path, proof_path = paths[0 if role == "A" else 3], paths[2 if role == "A" else 5]
            launch_path = trace_path.with_name(trace_path.name + ".launch.json")
            report["provenance"][role + ":launch"] = {}
            require(output.resolve() != launch_path.resolve(), "output overlaps launcher receipt")
            launch = json_value(read_input(launch_path, JSON_LIMIT, report["provenance"][role + ":launch"]))
            arm["launcherReceipt"] = launch
            verify_launch(launch, manifest, contract["protocol"], report["provenance"]["pins"]["sha256"], report["provenance"]["protocol"]["sha256"],
                          report["provenance"]["wrapperSource"]["sha256"], trace_path, manifest_path, proof_path)
            parsed[role] = inspect_arm(data[role + ":trace"], manifest, proof, arm, launch)
        except (OSError, EvidenceError, ValueError, TypeError, KeyError, IndexError, UnicodeError) as error:
            report["errors"].append({"scope": role, "message": str(error)})
    if len(parsed) == 2:
        try:
            left, right = (report["arms"][role] for role in ("A", "B"))
            for key in ("row", "descriptor", "mechanism", "nodeVersion", "nodeMajor", "fallbackHook"):
                require(left["manifest"][key] == right["manifest"][key], "paired binding differs: " + key)
            require(left["launcherReceipt"]["runtime"]["sha256"] == right["launcherReceipt"]["runtime"]["sha256"], "paired Node runtime binaries differ")
            require(left["launcherReceipt"]["denialWrapper"] == right["launcherReceipt"]["denialWrapper"], "paired denial-wrapper build receipts differ")
            require(left["manifest"]["nativeSha256"] != right["manifest"]["nativeSha256"], "A/B native binaries unexpectedly identical despite separate changed-source builds")
            require(left["manifest"]["rootPath"] != right["manifest"]["rootPath"], "A/B roots are not distinct")
            require(len(left["manifest"]["rootPath"].encode("utf-8")) == len(right["manifest"]["rootPath"].encode("utf-8")),
                    "A/B root byte lengths differ; readlink return lengths must stay comparable")
            require(left["publicProof"]["outcome"] == right["publicProof"]["outcome"], "public outcomes differ")
            report["comparison"] = compare(report["arms"], parsed, left["manifest"]["descriptor"])
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
