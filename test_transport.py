# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

def redirect_to_plaintext_is_refused():
    class Redirector(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "http://203.0.113.7/v1/node_info")
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = qcore.Client(f"http://127.0.0.1:{server.server_address[1]}")
        client.node_info()
    except (ValueError, RuntimeError):
        return True
    except Exception:
        return False
    finally:
        server.shutdown()
    return False

def an_environment_proxy_is_ignored():
    class Info(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            payload = b'{"chain_id": "Q-dev-net-1"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = HTTPServer(("127.0.0.1", 0), Info)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    dead = "http://127.0.0.1:9"
    env = dict(os.environ, HTTP_PROXY=dead, HTTPS_PROXY=dead, http_proxy=dead, https_proxy=dead,
               ALL_PROXY=dead, all_proxy=dead, NO_PROXY="", no_proxy="")
    probe = (
        "import os, sys\n"
        "sys.path.append(os.path.join(sys.argv[1], 'python'))\n"
        "import qcore\n"
        "print(qcore.Client(sys.argv[2]).node_info()['chain_id'])\n"
    )
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        result = subprocess.run(
            [sys.executable, "-c", probe, here, f"http://127.0.0.1:{server.server_address[1]}"],
            env=env, capture_output=True, text=True, timeout=60,
        )
    finally:
        server.shutdown()
    return result.returncode == 0 and result.stdout.strip() == "Q-dev-net-1"

def rejects(base):
    try:
        qcore.Client(base)
    except ValueError:
        return True
    return False

def accepts(base):
    try:
        qcore.Client(base)
    except ValueError:
        return False
    return True

def main():
    assert accepts("http://127.0.0.1:8080"), "loopback http must be accepted"
    assert accepts("http://localhost:8080"), "localhost http must be accepted"
    assert accepts("http://[::1]:8080"), "ipv6 loopback http must be accepted"
    assert accepts("https://gateway.quantova.example"), "https must be accepted"
    assert accepts("https://203.0.113.7:443"), "https to a public host must be accepted"

    assert rejects("http://203.0.113.7:8080"), "plaintext http to a public ip must be refused"
    assert rejects("http://gateway.quantova.example"), "plaintext http to a public host must be refused"
    assert rejects("ftp://127.0.0.1:21"), "a non http scheme must be refused"
    assert rejects("127.0.0.1:8080"), "a base with no scheme must be refused"

    assert redirect_to_plaintext_is_refused(), "a redirect to a plaintext non loopback host must be refused"
    assert an_environment_proxy_is_ignored(), "a proxy named in the environment must never carry gateway traffic"

    print("transport guard: all cases passed")

if __name__ == "__main__":
    main()
