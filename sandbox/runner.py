"""Runs inside the offline container. Bounds commands without leaving orphan processes."""

import json
import os
import selectors
import signal
import subprocess
import sys
import time


def main():
    request = json.loads(sys.stdin.buffer.read(400_000))
    command = ["python3", "-c", request["code"]] if request["kind"] == "python" else ["bash", "-lc", request["code"]]
    timeout = min(max(int(request.get("timeout", 120)), 1), 300)
    limit = 48_000
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    timed_out, truncated = False, False
    try:
        while selector.get_map():
            if time.monotonic() > deadline:
                timed_out = True
                break
            for key, _ in selector.select(timeout=0.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                remaining = max(0, limit - len(buffer))
                truncated |= len(chunk) > remaining
                buffer.extend(chunk[:remaining])
        if not timed_out:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        # Kill descendants even if the command's parent exited before its children.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    print(json.dumps({
        "exit_code": process.returncode, "timed_out": timed_out, "truncated": truncated,
        **{name: value.decode("utf-8", "replace") for name, value in buffers.items()},
    }))


if __name__ == "__main__":
    main()
