"""Protect the reviewed bounded helper's settlement from repeated cancellation."""
import signal
import bounded

SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


def install():
    original_settle = bounded.settle

    def settle_without_interruption(child, term_seconds=3):
        previous = {sig: signal.signal(sig, signal.SIG_IGN)
                    for sig in SIGNALS}
        try:
            return original_settle(child, term_seconds=term_seconds)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    def cancel(signum, _frame):
        # A second TERM must not interrupt the active owner's finally/settle.
        for sig in SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        raise InterruptedError(f"received signal {signum}")

    bounded.settle = settle_without_interruption
    for sig in SIGNALS:
        signal.signal(sig, cancel)


def joined(receipt):
    return receipt.get("localProcessSettled") is True and not receipt.get("cleanupErrors")
