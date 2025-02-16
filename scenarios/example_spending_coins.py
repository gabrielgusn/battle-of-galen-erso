#!/usr/bin/env python3

import socket
import time

from commander import Commander

import decimal

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
from test_framework.script import CScript, OP_RETURN
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
        txid = int(utxos[0]["txid"], 16)
        vout = utxos[0]["vout"]

        # self.log.info(f"utxos {utxos}")

        tx_arr = []
        i=0

        for i, utxo in enumerate(utxos):
            print("starting with utxo", i)
            sec_tx = CTransaction()
            sec_tx.vin.append(CTxIn(COutPoint(txid, vout)))

            max_outs = utxo["amount"] / decimal.Decimal(0.00000500)
            # print(utxo["amount"])
            # print("max",int(max_outs))

            print(i," out of", tx_arr.__len__())
            for i in range(0,int(max_outs)):
                # print("appending utxo",i)
                sec_tx.vout.append(
                    CTxOut(
                        500,  # Smallest dust value (in satoshis)
                        CScript([OP_RETURN])  # OP_RETURN output (no spending required)
                    )
                )
        # sec_tx.vout.append(
        #     CTxOut(int(0.00009 * COIN), address_to_scriptpubkey(node.getnewaddress()))
        # )

            signed_tx = node.signrawtransactionwithwallet(sec_tx.serialize().hex())
            tx_arr.append(signed_tx)

        print("len", tx_arr.__len__())

        print("SIZE",sec_tx.get_vsize())
        print("SIZE",sec_tx.get_weight())      
        # print(signed_tx)  

        # raw_tx = node.create_raw_transaction(sec_tx.serialize())

        

        # self.log.info(f"signed_tx {signed_tx}")

        # tx = tx_from_hex(signed_tx["hex"])
        # attacker.send_and_ping(msg_tx(tx))


def main():
    SpendingCoins().main()


if __name__ == "__main__":
    main()
