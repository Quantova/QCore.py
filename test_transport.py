import os
import sys

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore


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

    print("transport guard: all cases passed")


if __name__ == "__main__":
    main()
