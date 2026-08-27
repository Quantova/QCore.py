# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import os
import socket
import sys
import threading
import time

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

def dribbler(status):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.recv(65536)
            conn.sendall(
                f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                f"Content-Length: 1000000\r\n\r\n".encode()
            )
            for _ in range(20):
                time.sleep(0.2)
                try:
                    conn.sendall(b" ")
                except OSError:
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, port

def timed_call(port):
    client = qcore.Client(f"http://127.0.0.1:{port}")
    start = time.monotonic()
    try:
        client.node_info()
    except Exception as err:  # noqa: BLE001 - the test classifies the failure below
        return time.monotonic() - start, err
    return time.monotonic() - start, None

def main():
    saved = qcore._DEADLINE_SECONDS
    qcore._DEADLINE_SECONDS = 1.0
    budget = 2.5
    try:
        for label, status in (("a dribbled reply", "200 OK"),
                              ("a dribbled error body", "500 Internal Server Error")):
            srv, port = dribbler(status)
            try:
                elapsed, err = timed_call(port)
            finally:
                srv.close()
            if err is None:
                print(f"FAIL {label} was not cut off, it returned after {elapsed:.1f}s")
                sys.exit(1)
            if "did not arrive in time" not in str(err):
                print(f"FAIL {label} raised the wrong error after {elapsed:.1f}s: {err}")
                sys.exit(1)
            if elapsed > budget:
                print(f"FAIL {label} was cut off but only after {elapsed:.1f}s, past the budget")
                sys.exit(1)
            print(f"  ok   {label} is cut off at the deadline in {elapsed:.1f}s")
    finally:
        qcore._DEADLINE_SECONDS = saved

    print("\nslow read: both the reply and the error path honour the read deadline")

if __name__ == "__main__":
    main()
