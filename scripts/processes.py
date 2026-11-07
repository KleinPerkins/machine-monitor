"""Bounded ownership for verification and standalone build subprocesses."""
import os
import signal
import subprocess
import time


def group_stopped(pgid):
    # Inspect state only inside this launch's own process group. No host-wide
    # inventory, command arguments or telemetry is read. macOS may report EPERM
    # rather than ESRCH when the only remaining member is an exited zombie.
    result = subprocess.run(['/bin/ps', '-g', str(pgid), '-o', 'stat='],
                            capture_output=True, text=True, timeout=3)
    if result.returncode not in (0, 1):
        raise RuntimeError('Owned process-group state unavailable')
    return all(state.startswith('Z') for state in result.stdout.split())


def send_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        if not group_stopped(pgid):
            raise
        return False


def run_owned(command, *, timeout, cwd=None, env=None):
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    def terminated(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminated)
    process = None
    deferred = []
    def defer_termination(signum, _frame):
        if not deferred:
            deferred.append(signum)
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True)
        code = process.wait(timeout=timeout)
        if code:
            raise subprocess.CalledProcessError(code, command)
    finally:
        # Finish cleanup, then honor cancellation that first arrives here.
        for signum in previous:
            signal.signal(signum, defer_termination)
        try:
            if process is not None:
                try:
                    if send_group(process.pid, signal.SIGTERM):
                        time.sleep(3)
                        send_group(process.pid, signal.SIGKILL)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    if deferred:
        raise SystemExit(128 + deferred[0])


def run_build(command, *, cwd=None, env=None, timeout=300):
    if os.environ.get('MONITOR_OWNED_SHARD_GROUP') == '1':
        # Build children stay in the bounded supervisor's group. On failure,
        # stop that worker group before its parent removes temporary state.
        try:
            subprocess.run(command, cwd=cwd, env=env, timeout=timeout, check=True)
        except BaseException:
            os.killpg(os.getpgrp(), signal.SIGTERM)
            raise
    else:
        run_owned(command, cwd=cwd, env=env, timeout=timeout)
