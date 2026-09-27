#!/usr/bin/env python3
"""One Linux fixture volume; invoke every setup/cleanup through step-owner.py.

The caller creates WORK once, outside transport/evidence, and settles every
product process before cleanup. Each of the three cleanups gets its own bounded
step, even after earlier failure/timeouts. Commands inherit that owner's group.
Images stay in WORK after cleanup and must never enter the evidence archive.

Prepare all three intents before the first setup. Commands:
mount-owner.py prepare|setup|cleanup --volume ID --work-dir WORK --state-file JSON
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


SPECS = {
    "xfs": (2147483648, "xfs", ["mkfs.xfs", "-q", "-m", "reflink=1"]),
    "btrfs": (2147483648, "btrfs", ["mkfs.btrfs", "-q"]),
    "xfs-no-reflink": (1073741824, "xfs", ["mkfs.xfs", "-q", "-m", "reflink=0"]),
}
MOUNT_COLUMNS = "TARGET,SOURCE,FSTYPE,MAJ:MIN,FSROOT,ID"
LOOP_COLUMNS = "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def identity(path, kind):
    info = os.lstat(path)
    require(Path(path).resolve() == Path(path), f"noncanonical path: {path}")
    predicate = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
    require(predicate(info.st_mode), f"unexpected {kind} type: {path}")
    require(info.st_uid == os.getuid(), f"foreign owner: {path}")
    require(not info.st_mode & 0o022, f"group/other-writable path: {path}")
    if kind == "file":
        require(info.st_nlink == 1, f"multiply linked image/state: {path}")
    return {"dev": info.st_dev, "ino": info.st_ino}


def save(path, state, *, initial=False):
    if initial:
        with path.open("x", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return
    identity(path, "file")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(state, state_file, argv, allowed=(0,)):
    entry = {"argv": argv, "startedAt": now(), "exitCode": None}
    state["commands"].append(entry)
    save(state_file, state)
    try:
        # No shell, internal timeout, new session, or detached child. The
        # reviewed enclosing step owns timeout, termination, and group joining.
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, env={**os.environ, "LC_ALL": "C"})
        entry.update(exitCode=result.returncode, completedAt=now(),
                     stdout=result.stdout[:65536], stderr=result.stderr[:65536])
        require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
                f"oversized command output: {argv[0]}")
        require(result.returncode in allowed, f"command exited {result.returncode}: {argv}")
        return result
    except Exception as error:
        entry["error"] = str(error)
        raise
    finally:
        save(state_file, state)


def find_mounts(state, state_file, selector, value):
    result = command(state, state_file,
                     ["findmnt", "--json", "--list", "--nofsroot", "--output",
                      MOUNT_COLUMNS, selector, value], (0, 1))
    rows = json.loads(result.stdout)["filesystems"] if result.stdout.strip() else []
    require(isinstance(rows, list), "invalid findmnt response")
    require(result.returncode == 0 or (not rows and not result.stderr.strip()),
            "findmnt absence was not established")
    return rows


def mount_at(state, state_file):
    mount = state["mount"]
    if os.path.lexists(mount):
        require(stat.S_ISDIR(os.lstat(mount).st_mode), "mount path is not a directory")
    result = command(state, state_file, ["mountpoint", "-q", "--", mount], (0, 1, 32))
    require(result.returncode != 1 or not os.path.lexists(mount),
            "mountpoint could not inspect existing directory")
    rows = find_mounts(state, state_file, "--mountpoint", mount)
    require((result.returncode == 0) == bool(rows), "mountpoint/findmnt disagree")
    require(len(rows) <= 1, "ambiguous stacked mount identity")
    if rows:
        require(rows[0]["target"] == mount, "foreign mount target")
    return rows[0] if rows else None


def check_root(state):
    require(identity(state["workDir"], "directory") == state["workIdentity"],
            "fixture directory identity changed")


def check_image(state):
    require(state["imageIdentity"] is not None, "image identity was never recorded")
    require(identity(state["image"], "file") == state["imageIdentity"],
            "image identity changed")


def mount_table():
    def decode(value):
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)

    rows = []
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            before, after = line.split(" - ", 1)
            fields, filesystem = before.split(), after.split()
            rows.append({"deviceNumber": fields[2], "target": decode(fields[4]),
                         "filesystem": filesystem[0], "source": decode(filesystem[1])})
    return rows


def require_unmounted_loop(state, loop):
    devices = {loop["deviceNumber"]}
    if state["mounted"] is not None:
        devices.add(state["mounted"]["findmnt"]["maj:min"])
    for row in mount_table():
        require(row["deviceNumber"] not in devices, "owned device still has a mount")
        if state["filesystem"] == "btrfs" and row["filesystem"] == "btrfs":
            # Btrfs subvolumes may have different anonymous filesystem devices.
            # Resolve every remaining Btrfs source to its backing block device;
            # an unknown source cannot establish that our loop is unused.
            require(os.path.isabs(row["source"]), "unknown remaining Btrfs mount source")
            source = os.stat(row["source"])
            require(stat.S_ISBLK(source.st_mode), "remaining Btrfs source is not a block device")
            require(f"{os.major(source.st_rdev)}:{os.minor(source.st_rdev)}" != loop["deviceNumber"],
                    "owned loop has a Btrfs mount under another source spelling")


def loops_for_image(state, state_file):
    check_root(state)
    if state["imageIdentity"] is None:
        require(not state["mountAttempted"] and not os.path.lexists(state["image"]),
                "unrecorded image/attempt; ownership cannot be established")
        # An untouched prepare intent cannot have issued mount/loop commands.
        return []
    check_image(state)
    result = command(state, state_file,
                     ["sudo", "-n", "losetup", "--json", "--list", "--associated",
                      state["image"], "--output", LOOP_COLUMNS])
    rows = json.loads(result.stdout)["loopdevices"] if result.stdout.strip() else []
    require(isinstance(rows, list), "invalid losetup response")
    require(len({row.get("name") for row in rows}) == len(rows), "duplicate loop identities")
    for row in rows:
        check_image(state)
        name = row.get("name", "")
        require(re.fullmatch(r"/dev/loop[0-9]+", name), "foreign device name")
        info = os.lstat(name)
        require(stat.S_ISBLK(info.st_mode), "loop device is not a block device")
        require(row.get("back-file") == state["image"], "foreign loop backing path")
        require(int(row.get("back-ino", -1)) == state["imageIdentity"]["ino"],
                "foreign loop backing inode")
        dev = state["imageIdentity"]["dev"]
        require(row.get("back-maj:min") == f"{os.major(dev)}:{os.minor(dev)}",
                "foreign loop backing device")
        require(int(row.get("offset", -1)) == 0 and int(row.get("sizelimit", -1)) == 0
                and row.get("ro") in (False, 0), "unexpected loop configuration")
        row["deviceNumber"] = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    return rows


def admit_mount(state, row, loops):
    require(state["mountAttempted"], "mount exists without task-owned mount intent")
    require(row is not None and len(loops) == 1, "mounted image association is ambiguous")
    loop = loops[0]
    require(row["source"] == loop["name"], "mount uses a foreign device source")
    require(row["fstype"] == state["filesystem"] and row["fsroot"] == "/",
            "foreign filesystem or subvolume mounted at fixture root")
    if state["filesystem"] == "btrfs":
        # Btrfs mountinfo identifies an anonymous filesystem device, not st_rdev
        # of its backing loop. Keep both identities through unmount and detach.
        require(re.fullmatch(r"0:[1-9][0-9]*", row["maj:min"]),
                "unexpected Btrfs filesystem device identity")
    else:
        require(row["maj:min"] == loop["deviceNumber"], "XFS mount uses a foreign device")
    if state["mounted"] is not None:
        require(row == state["mounted"]["findmnt"], "recorded mount identity changed")
    return loop


def setup(state, state_file):
    state["setup"] = {"ok": False, "startedAt": now(), "error": None}
    save(state_file, state)
    try:
        check_root(state)
        require(not os.path.lexists(state["image"]) and not os.path.lexists(state["mount"]),
                "fixture paths already exist")
        os.mkdir(state["mount"], 0o700)
        state["mountDirectoryIdentity"] = identity(state["mount"], "directory")
        save(state_file, state)
        descriptor = os.open(state["image"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            state["imageIdentity"] = identity(state["image"], "file")
            save(state_file, state)
            os.ftruncate(descriptor, state["sizeBytes"])
        finally:
            os.close(descriptor)
        require(mount_at(state, state_file) is None, "fixture path is already mounted")
        require(not loops_for_image(state, state_file), "new image already has a loop association")
        command(state, state_file, SPECS[state["volume"]][2] + [state["image"]])
        check_image(state)
        require(identity(state["mount"], "directory") == state["mountDirectoryIdentity"],
                "mount directory identity changed before setup")
        state["mountAttempted"] = True
        save(state_file, state)
        command(state, state_file, ["sudo", "-n", "mount", "-o", "loop", "--",
                                    state["image"], state["mount"]])
        row = mount_at(state, state_file)
        loop = admit_mount(state, row, loops_for_image(state, state_file))
        state["mounted"] = {"findmnt": row, "loop": loop}
        save(state_file, state)
        command(state, state_file, ["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}",
                                    "--", state["mount"]])
        admit_mount(state, mount_at(state, state_file), loops_for_image(state, state_file))
        info = os.lstat(state["mount"])
        require((info.st_uid, info.st_gid) == (os.getuid(), os.getgid()), "runner ownership mismatch")
        state["runnerOwnership"] = {"uid": info.st_uid, "gid": info.st_gid}
        state["setup"]["ok"] = True
    except Exception as error:
        state["setup"]["error"] = str(error)
    finally:
        state["setup"]["completedAt"] = now()
        save(state_file, state)
    return state["setup"]["ok"]


def cleanup(state, state_file):
    result = {"ok": False, "startedAt": now(), "mountAbsent": False,
              "loopsAbsent": False, "errors": [], "imagesRetainedOutsideEvidence": True}
    state["cleanup"] = result
    save(state_file, state)
    try:
        check_root(state)
        row = mount_at(state, state_file)
        if row is not None:
            loop = admit_mount(state, row, loops_for_image(state, state_file))
            if state["mounted"] is None:
                # Recover the filesystem identity if setup stopped after mount
                # but before publishing its observation receipt.
                state["mounted"] = {"findmnt": row, "loop": loop}
                save(state_file, state)
            command(state, state_file, ["sudo", "-n", "umount", "--", state["mount"]])
    except Exception as error:
        result["errors"].append("unmount: " + str(error))
    # A nonzero umount must not suppress independent absence verification.
    try:
        check_root(state)
        require(mount_at(state, state_file) is None, "mount remains after cleanup")
        require(not any(row["target"] == state["mount"] or row["target"].startswith(state["mount"] + "/")
                        for row in mount_table()), "mount or descendant remains in mountinfo")
        if state["mountDirectoryIdentity"] is not None:
            require(identity(state["mount"], "directory") == state["mountDirectoryIdentity"],
                    "underlying mount directory identity changed")
        result["mountAbsent"] = True
    except Exception as error:
        result["errors"].append("mount absence: " + str(error))
    try:
        rows = loops_for_image(state, state_file)
        result["imageWasNeverCreated"] = state["imageIdentity"] is None
        result["loopsBeforeDetach"] = rows
        for loop in rows:
            require(state["mountAttempted"] and result["mountAbsent"],
                    "cannot detach without owned mount intent and proven absence")
            require(not find_mounts(state, state_file, "--source", loop["name"]),
                    "owned loop device is still mounted elsewhere")
            require_unmounted_loop(state, loop)
            # mount -o loop normally autoclears; recheck before an explicit detach.
            current = loops_for_image(state, state_file)
            match = [item for item in current if item["name"] == loop["name"]]
            if not match:
                continue
            require(match == [loop], "loop association changed before detach")
            require_unmounted_loop(state, loop)
            command(state, state_file, ["sudo", "-n", "losetup", "--detach", loop["name"]])
        require(not loops_for_image(state, state_file), "image retains loop associations")
        result["loopsAbsent"] = True
    except Exception as error:
        result["errors"].append("loop cleanup: " + str(error))
    result["ok"] = result["mountAbsent"] and result["loopsAbsent"] and not result["errors"]
    result["completedAt"] = now()
    save(state_file, state)
    return result["ok"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "setup", "cleanup"))
    parser.add_argument("--volume", required=True, choices=SPECS)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--state-file", required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == "linux", "mount lifecycle requires Linux")
    work, state_file = args.work_dir, args.state_file
    require(work.is_absolute() and state_file.is_absolute(), "paths must be absolute")
    require(state_file.parent.resolve() == state_file.parent, "state parent is not canonical")
    work_identity = identity(work, "directory")
    for volume in SPECS:
        require(not state_file.is_relative_to(work / volume)
                and state_file != work / (volume + ".img"), "state overlaps mount assets")
    size, filesystem, _ = SPECS[args.volume]
    expected = {"schema": 1, "volume": args.volume, "workDir": str(work),
                "workIdentity": work_identity, "image": str(work / (args.volume + ".img")),
                "mount": str(work / args.volume), "sizeBytes": size, "filesystem": filesystem}
    if args.action == "prepare":
        require(not os.path.lexists(expected["image"]) and not os.path.lexists(expected["mount"]),
                "fixture paths already exist before ownership intent")
        state = {**expected, "intentRecordedAt": now(), "imageIdentity": None,
                 "mountDirectoryIdentity": None, "mountAttempted": False, "mounted": None,
                 "prepare": {"ok": True}, "setup": {"ok": False},
                 "cleanup": {"ok": False}, "commands": []}
        save(state_file, state, initial=True)
    else:
        identity(state_file, "file")
        state = json.loads(state_file.read_text(encoding="utf-8"))
        require(all(state.get(key) == value for key, value in expected.items()), "foreign state identity")
    if args.action == "setup":
        require("startedAt" not in state["setup"] and "startedAt" not in state["cleanup"],
                "setup intent was already consumed")
        ok = setup(state, state_file)
    else:
        ok = True if args.action == "prepare" else cleanup(state, state_file)
    print(json.dumps({"volume": args.volume, "action": args.action, "ok": ok,
                      "stateFile": str(state_file), "result": state[args.action]}), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}), flush=True)
        sys.exit(1)
