"""Finalize only complete, settled qualification evidence for artifact upload."""
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tarfile

if not __debug__:
    raise RuntimeError("evidence publication requires assertion checks")

work = Path(sys.argv[1])
archive = work / "results.tar.gz"
evidence = work / "evidence"
receipt = json.loads((evidence / "control/archive.exit.json").read_text())
assert receipt["exitCode"] == 0 and receipt["failure"] is None
assert receipt["localProcessSettled"] is True and receipt["cleanupErrors"] == []
gates = json.loads((evidence / "final-gates.json").read_text())
assert gates["allProcessGroupsSettled"] is True and gates["allVolumesReleased"] is True
with gzip.open(archive, "rb") as stream:
    while stream.read(1024 * 1024):
        pass
with tarfile.open(archive, "r:gz") as stream:
    for member in stream:
        name = PurePosixPath(member.name)
        assert not name.is_absolute() and ".." not in name.parts
        assert name.parts and name.parts[0] == "evidence"
        assert member.isdir() or member.isfile()
final = work / "settled-evidence.tar.gz"
assert not final.exists()
os.replace(archive, final)
with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
    stream.write(f"PROOF_ARCHIVE={final}\n")
print("Complete settled evidence finalized for upload")
