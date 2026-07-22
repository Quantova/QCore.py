import os
import sys

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore


def main():
    seed = "11" * 32
    good = qcore.address(seed, 0)

    signed = qcore.sign_transfer(seed, 0, good, 5, 0, 1)
    assert "tx_hex" in signed, "a valid recipient must sign"

    signed = qcore.sign_call(seed, 0, good, "", 0, 1000, 1)
    assert "tx_hex" in signed, "a valid target must sign"

    for bad in ("not an address", "", "Q1zzzz", good[:-1] + ("q" if good[-1] != "q" else "p")):
        try:
            qcore.sign_transfer(seed, 0, bad, 5, 0, 1)
        except ValueError:
            pass
        else:
            raise AssertionError(f"sign_transfer signed a bad recipient {bad!r}")
        try:
            qcore.sign_call(seed, 0, bad, "", 0, 1000, 1)
        except ValueError:
            pass
        else:
            raise AssertionError(f"sign_call signed a bad target {bad!r}")

    print("exported sign validation: all cases passed")


if __name__ == "__main__":
    main()
