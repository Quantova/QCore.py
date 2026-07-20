# Prove the Python binding end to end against a running gateway. The native core signs
# and builds every request, this test only does the HTTP and reads the fields.
import sys, time, qcore

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8645"
client = qcore.Client(url)
seed = "0b" * 32  # the [11; 32] seed the proof accounts derive from

info = client.node_info()
print("network", info["chain_id"], "fee", info["fee"]["transfer_quon"], info["denomination"])

to = client.address(seed, 1)
# Accept a fee no higher than what node info reported, so a gateway cannot inflate it and drain us.
signed, outcome = client.transfer(seed, 0, to, 1000, info["fee"]["transfer_quon"])
print("submitted", signed["tx_id"], outcome["verdict"], outcome.get("state") or outcome.get("reason"))
assert outcome["verdict"] == "accepted", "not accepted"

for _ in range(40):
    s = client.transaction(signed["tx_id"])
    if s["status"] == "finalised":
        print("finalised at height", s["height"], "in", s["block"]); break
    time.sleep(0.25)

a = client.account(signed["from"])
print("sender now balance", a["balance"], "nonce", a["nonce"])
print("OK")
