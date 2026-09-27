"""One Windows Job Object step; source-only until validated on Windows.

Usage: python windows-step-owner.py PROCESS_DIR LABEL CAP COMMAND ARGS...
COMMAND must be a native executable; pass an explicit interpreter for scripts.
Cwd and environment are inherited. No environment values are recorded.
Requires creation-time Job List support (Windows 10 / Server 2016 or later);
unsupported attribute or job assignment fails closed, without a fallback.
An abruptly killed owner relies on KILL_ON_JOB_CLOSE and has no exit receipt;
the caller must reject missing or unsettled receipts before collection.
"""
import datetime
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

SETTLE_SECONDS = 7
TERMINATED_EXIT_CODE = 0xE0000001


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def run(directory, label, cap, argv):
    # Keep all platform code inside run; inspection must not load Windows APIs.
    if os.name != "nt":
        raise RuntimeError("windows-step-owner requires Windows")
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt

    class Limits(c.Structure):
        _fields_ = [("PerProcessUserTimeLimit", c.c_int64), ("PerJobUserTimeLimit", c.c_int64),
                    ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", c.c_size_t),
                    ("MaximumWorkingSetSize", c.c_size_t), ("ActiveProcessLimit", w.DWORD),
                    ("Affinity", c.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

    class IoCounters(c.Structure):
        _fields_ = [(name, c.c_uint64) for name in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class ExtendedLimits(c.Structure):
        _fields_ = [("BasicLimitInformation", Limits), ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", c.c_size_t), ("JobMemoryLimit", c.c_size_t),
                    ("PeakProcessMemoryUsed", c.c_size_t), ("PeakJobMemoryUsed", c.c_size_t)]

    class Accounting(c.Structure):
        _fields_ = [(name, c.c_int64) for name in
                    ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime")] + [
                    (name, w.DWORD) for name in
                    ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses")]

    class StartupInfo(c.Structure):
        _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR)] + [
                    (name, w.DWORD) for name in
                    ("dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")] + [
                    ("wShowWindow", w.WORD), ("cbReserved2", w.WORD), ("lpReserved2", c.POINTER(w.BYTE)),
                    ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

    class StartupInfoEx(c.Structure):
        _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", c.c_void_p)]

    class ProcessInfo(c.Structure):
        _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

    kernel = c.WinDLL("kernel32", use_last_error=True)

    def api(name, restype, *args):
        fn = getattr(kernel, name)
        fn.restype = restype
        fn.argtypes = args
        return fn

    create_job = api("CreateJobObjectW", w.HANDLE, c.c_void_p, w.LPCWSTR)
    set_job = api("SetInformationJobObject", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD)
    query_job = api("QueryInformationJobObject", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p)
    is_process_in_job = api("IsProcessInJob", w.BOOL, w.HANDLE, w.HANDLE, c.POINTER(w.BOOL))
    terminate_job = api("TerminateJobObject", w.BOOL, w.HANDLE, w.UINT)
    terminate_process = api("TerminateProcess", w.BOOL, w.HANDLE, w.UINT)
    wait = api("WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
    get_exit = api("GetExitCodeProcess", w.BOOL, w.HANDLE, c.POINTER(w.DWORD))
    resume = api("ResumeThread", w.DWORD, w.HANDLE)
    close = api("CloseHandle", w.BOOL, w.HANDLE)
    init_attrs = api("InitializeProcThreadAttributeList", w.BOOL, c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t))
    update_attrs = api("UpdateProcThreadAttribute", w.BOOL, c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p)
    delete_attrs = api("DeleteProcThreadAttributeList", None, c.c_void_p)
    create_process = api("CreateProcessW", w.BOOL, w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p,
                         w.BOOL, w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(StartupInfoEx), c.POINTER(ProcessInfo))

    def checked(result, operation):
        if not result:
            raise OSError(f"{operation} failed with Windows error {c.get_last_error()}")
        return result

    def root_done():
        if not process.hProcess:
            return True
        result = wait(process.hProcess, 0)
        if result == 0:
            return True
        if result == 0x102:  # WAIT_TIMEOUT
            return False
        raise OSError(f"WaitForSingleObject failed: result={result}, Windows error={c.get_last_error()}")

    def active_count():
        if not job:
            return 0
        info = Accounting()
        checked(query_job(job, 1, c.byref(info), c.sizeof(info), None), "QueryInformationJobObject")
        return info.ActiveProcesses

    interrupted = [None]

    def stop_signal(signum, frame):
        # Do not raise between CreateProcess returning and ownership bookkeeping.
        # Polling observes cancellation; repeated signals cannot interrupt cleanup.
        if interrupted[0] is None:
            interrupted[0] = signum

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGBREAK):
        signal.signal(sig, stop_signal)

    def check_cancelled():
        if interrupted[0] is not None:
            raise InterruptedError(f"received signal {interrupted[0]}")

    directory.mkdir(parents=True, exist_ok=True)
    save(directory / f"{label}.request.json", {
        "argv": argv, "cwd": os.getcwd(), "capSeconds": cap, "startedAt": now(),
        "settleSeconds": SETTLE_SECONDS, "owner": "windows-job-object", "environment": "inherited; values omitted",
    })
    print(json.dumps({"phase": label, "startedAt": now(), "capSeconds": cap}), flush=True)
    start = time.monotonic()
    deadline = start + cap
    process = ProcessInfo()
    job = None
    attrs = None
    assigned = False
    resumed = False
    root_joined = False
    active = None
    exit_code = None
    failure = None
    cleanup_errors = []
    streams = []
    try:
        check_cancelled()
        streams.append(open(os.devnull, "rb"))
        streams.append((directory / f"{label}.stdout.log").open("xb"))
        streams.append((directory / f"{label}.stderr.log").open("xb"))
        handles = (w.HANDLE * 3)(*(msvcrt.get_osfhandle(stream.fileno()) for stream in streams))
        for stream in streams:
            os.set_inheritable(stream.fileno(), True)
        # NULL security attributes make this handle non-inheritable. No breakaway flags.
        job = checked(create_job(None, None), "CreateJobObjectW")
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        checked(set_job(job, 9, c.byref(limits), c.sizeof(limits)), "SetInformationJobObject")
        size = c.c_size_t()
        init_attrs(None, 2, 0, c.byref(size))
        if not size.value:
            raise OSError(f"attribute-list sizing failed with Windows error {c.get_last_error()}")
        attrs_buffer = c.create_string_buffer(size.value)
        checked(init_attrs(attrs_buffer, 2, 0, c.byref(size)), "InitializeProcThreadAttributeList")
        attrs = attrs_buffer
        checked(update_attrs(attrs, 0, 0x20002, handles, c.sizeof(handles), None, None), "UpdateProcThreadAttribute(HANDLE_LIST)")
        # Kernel assignment during creation closes the owner-death gap before resume.
        job_handles = (w.HANDLE * 1)(job)
        checked(update_attrs(attrs, 0, 0x2000D, job_handles, c.sizeof(job_handles), None, None),
                "UpdateProcThreadAttribute(JOB_LIST)")
        startup = StartupInfoEx()
        startup.StartupInfo.cb = c.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = handles
        startup.lpAttributeList = c.cast(attrs, c.c_void_p)
        executable = shutil.which(argv[0])
        if not executable:
            raise FileNotFoundError("command executable was not found")
        command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
        check_cancelled()
        # CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT; never CREATE_BREAKAWAY_FROM_JOB.
        checked(create_process(executable, command, None, None, True, 0x4 | 0x80000,
                               None, os.getcwd(), c.byref(startup), c.byref(process)), "CreateProcessW")
        membership = w.BOOL()
        checked(is_process_in_job(process.hProcess, job, c.byref(membership)), "IsProcessInJob")
        if not membership.value:
            raise RuntimeError("created child is not a member of the required job")
        assigned = True
        check_cancelled()
        if time.monotonic() >= deadline:
            raise TimeoutError(f"command exceeded {cap} seconds before resume")
        if resume(process.hThread) == 0xFFFFFFFF:
            raise OSError(f"ResumeThread failed with Windows error {c.get_last_error()}")
        resumed = True
        while True:
            check_cancelled()
            if time.monotonic() >= deadline:
                raise TimeoutError(f"command exceeded {cap} seconds")
            if root_done():
                root_joined = True
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except BaseException as error:
        failure = repr(error)
    finally:
        # Each kernel call below is synchronous; only this fixed deadline owns settlement.
        settle_deadline = time.monotonic() + SETTLE_SECONDS
        try:
            root_joined = root_done()
            active = active_count()
            if root_joined and active and failure is None:
                cleanup_errors.append("command exited leaving active job processes")
        except BaseException as error:
            cleanup_errors.append(repr(error))
        if job and (active != 0 or not root_joined):
            try:
                checked(terminate_job(job, TERMINATED_EXIT_CODE), "TerminateJobObject")
            except BaseException as error:
                cleanup_errors.append(repr(error))
        # Fail closed if the suspended root's creation-time membership was not confirmed.
        if process.hProcess and not assigned and not root_joined:
            try:
                checked(terminate_process(process.hProcess, TERMINATED_EXIT_CODE), "TerminateProcess")
            except BaseException as error:
                cleanup_errors.append(repr(error))
        while True:
            try:
                root_joined = root_done()
                active = active_count()
            except BaseException as error:
                root_joined = False
                active = None
                cleanup_errors.append(repr(error))
                break
            if root_joined and active == 0:
                break
            if time.monotonic() >= settle_deadline:
                cleanup_errors.append("job or root process did not settle within seven seconds")
                break
            time.sleep(min(0.05, max(0, settle_deadline - time.monotonic())))
        if process.hProcess and root_joined:
            try:
                code = w.DWORD()
                checked(get_exit(process.hProcess, c.byref(code)), "GetExitCodeProcess")
                exit_code = code.value
            except BaseException as error:
                cleanup_errors.append(repr(error))
        # Query the job before closing it; close is only a final safety net, never exit proof.
        for name, handle in (("thread", process.hThread), ("process", process.hProcess), ("job", job)):
            if handle:
                try:
                    checked(close(handle), f"CloseHandle({name})")
                except BaseException as error:
                    cleanup_errors.append(repr(error))
        if attrs is not None:
            delete_attrs(attrs)
        for stream in reversed(streams):
            try:
                stream.close()
            except BaseException as error:
                cleanup_errors.append(repr(error))
        if interrupted[0] is not None and failure is None:
            failure = repr(InterruptedError(f"received signal {interrupted[0]}"))
        receipt = {
            "exitCode": exit_code, "failure": failure, "cleanupErrors": cleanup_errors,
            "localProcessSettled": root_joined and active == 0,
            "rootProcessJoined": root_joined, "jobActiveProcesses": active,
            "jobAssigned": assigned, "childResumed": resumed, "pid": process.dwProcessId or None,
            "elapsedSeconds": time.monotonic() - start, "completedAt": now(),
        }
        save(directory / f"{label}.exit.json", receipt)
    print(json.dumps({"phase": label, **receipt}), flush=True)
    return 0 if failure is None and not cleanup_errors and receipt["localProcessSettled"] and exit_code == 0 else 1


def main():
    if len(sys.argv) < 5:
        raise ValueError("expected PROCESS_DIR LABEL CAP COMMAND ARGS...")
    directory, label, cap_text, *argv = sys.argv[1:]
    cap = float(cap_text)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", label) or ".." in label:
        raise ValueError("invalid step label")
    if not math.isfinite(cap) or cap <= 0 or any("\0" in arg for arg in argv):
        raise ValueError("invalid cap or command")
    return run(Path(directory), label, cap, argv)


if __name__ == "__main__":
    sys.exit(main())
