import struct
import time
import os
import json
import hashlib

# Structs
class BlockHeader:
    def __init__(self, version, prev_block_hash, merkle_root, timestamp, bits, nonce):
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce


class Input:
    def __init__(self, txid, vout, prevout, scriptsig, scriptsig_asm, witness, is_coinbase, sequence):
        self.txid = txid
        self.vout = vout
        self.prevout = prevout
        self.scriptsig = scriptsig
        self.scriptsig_asm = scriptsig_asm
        self.witness = witness
        self.is_coinbase = is_coinbase
        self.sequence = sequence


class Prevout:
    def __init__(self, scriptpubkey, scriptpubkey_asm, scriptpubkey_type, value, scriptpubkey_address=None):
        self.scriptpubkey = scriptpubkey
        self.scriptpubkey_asm = scriptpubkey_asm
        self.scriptpubkey_type = scriptpubkey_type
        self.scriptpubkey_address = scriptpubkey_address
        self.value = value


class Transaction:
    def __init__(self, version, locktime, vin, vout):
        self.version = version
        self.locktime = locktime
        self.vin = vin
        self.vout = vout


class TxInfo:
    def __init__(self, txid, wtxid, fee, weight):
        self.txid = txid
        self.wtxid = wtxid
        self.fee = fee
        self.weight = weight


class TxWeight:
    def __init__(self, base_size, witness_size, weight):
        self.base_size = base_size
        self.witness_size = witness_size
        self.weight = weight


class MerkleNode:
    def __init__(self, left, data, right):
        self.left = left
        self.data = data
        self.right = right


# Initializations
blck_header = BlockHeader(
    version=7,
    prev_block_hash="0000000000000000000000000000000000000000000000000000000000000000",
    merkle_root="",
    timestamp=int(time.time()),
    bits=0x1f00ffff,
    nonce=0,
)

target = "0000ffff00000000000000000000000000000000000000000000000000000000"

def serialize_int(n):
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def sha(data):
    hash = hashlib.sha256(data).digest()
    return hash


def extract_json(filename):
    try:
        with open(filename, "r") as file:
            data = file.read()
        return data, None
    except Exception as e:
        return "", e


def detect_segwit(tx):
    for vin in tx.vin:
        if len(vin.witness) > 0:
            return True
    return False


def bytes_rev(data):
    return data[::-1]


def byte_arr_comp(a, b):
    if len(a) != len(b):
        raise ValueError("Not same length")

    for i in range(len(a)):
        if a[i] < b[i]:
            return -1
        elif a[i] > b[i]:
            return 1

    return 0


# Serialize Transaction
def serialize_transaction(tx):
    serialized = b""
    serialized += struct.pack("<I", tx.version)
    serialized += serialize_int(len(tx.vin))
    for vin in tx.vin:
        serialized += bytes_rev(bytes.fromhex(vin.txid))
        serialized += struct.pack("<I", vin.vout)
        scriptsig_bytes = bytes.fromhex(vin.scriptsig)
        length_scriptsig = len(scriptsig_bytes)
        serialized += serialize_int(length_scriptsig)
        serialized += scriptsig_bytes
        serialized += struct.pack("<I", vin.sequence)

    serialized += serialize_int(len(tx.vout))
    for vout in tx.vout:
        serialized += struct.pack("<Q", vout.value)
        script_pubkey_bytes = bytes.fromhex(vout.scriptpubkey)
        script_pubkey_len = len(script_pubkey_bytes)
        serialized += serialize_int(script_pubkey_len)
        serialized += script_pubkey_bytes

    serialized += struct.pack("<I", tx.locktime)
    return serialized


def segwit_serialize(tx):
    serialized = b""
    is_segwit = detect_segwit(tx)
    serialized += struct.pack("<I", tx.version)
    if is_segwit:
        serialized += b"\x00\x01"
    serialized += serialize_int(len(tx.vin))
    for vin in tx.vin:
        serialized += bytes_rev(bytes.fromhex(vin.txid))
        serialized += struct.pack("<I", vin.vout)
        scriptsig_bytes = bytes.fromhex(vin.scriptsig)
        length_scriptsig = len(scriptsig_bytes)
        serialized += serialize_int(length_scriptsig)
        serialized += scriptsig_bytes
        serialized += struct.pack("<I", vin.sequence)

    serialized += serialize_int(len(tx.vout))
    for vout in tx.vout:
        serialized += struct.pack("<Q", vout.value)
        script_pubkey_bytes = bytes.fromhex(vout.scriptpubkey)
        script_pubkey_len = len(script_pubkey_bytes)
        serialized += serialize_int(script_pubkey_len)
        serialized += script_pubkey_bytes

    if is_segwit:
        for vin in tx.vin:
            witness_count = len(vin.witness)
            serialized += serialize_int(witness_count)
            for witness in vin.witness:
                witness_bytes = bytes.fromhex(witness)
                witness_len = len(witness_bytes)
                serialized += serialize_int(witness_len)
                serialized += witness_bytes

    serialized += struct.pack("<I", tx.locktime)
    return serialized


def serialize_blck_header(blck_header):
    seriaelezed = b""
    seriaelezed += struct.pack("<I", blck_header.version)
    seriaelezed += bytes.fromhex(blck_header.prev_block_hash)
    seriaelezed += bytes.fromhex(blck_header.merkle_root)
    seriaelezed += struct.pack("<I", int(blck_header.timestamp))
    seriaelezed += struct.pack("<I", blck_header.bits)
    seriaelezed += struct.pack("<I", blck_header.nonce)
    return seriaelezed


# Merkle Tree
def create_mekrle_root(left_node, right_node, data):
    m_node = MerkleNode(None, None, None)
    if left_node is None and right_node is None:
        m_node.data = bytes_rev(data)
    else:
        prevHash = left_node.data + right_node.data
        m_node.data = sha(sha(prevHash))
    m_node.left = left_node
    m_node.right = right_node
    return m_node


def create_mekrle_tree(leaves):
    nodes = []

    for leaf in leaves:
        data = bytes.fromhex(leaf)
        node = create_mekrle_root(None, None, data)
        nodes.append(node)

    while len(nodes) > 1:
        new_lvl = []
        for i in range(0, len(nodes), 2):
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            node = create_mekrle_root(nodes[i], nodes[i + 1], None)
            new_lvl.append(node)
        nodes = new_lvl

    return nodes[0]


def craete_witness_merkrle():
    _, _, w_tx_ids = rank_trnsctions()
    w_tx_ids = ["0000000000000000000000000000000000000000000000000000000000000000"] + w_tx_ids
    merkleRoot = create_mekrle_tree(w_tx_ids)

    comm_string = merkleRoot.data.hex() + "0000000000000000000000000000000000000000000000000000000000000000"
    wit_comm = bytes.fromhex(comm_string)
    wit_comm = sha(sha(wit_comm))

    return wit_comm.hex()


# POW and Prioritize
def pow(blck_header: BlockHeader):
    target_bytes = bytes.fromhex(target)
    while True:
        serialized = serialize_blck_header(blck_header)
        hash = bytes_rev(sha(sha(serialized)))

        if byte_arr_comp(hash, target_bytes) == -1:

            return True
        if blck_header.nonce < 0x0 or blck_header.nonce > 0xffffffff:
            return False
        blck_header.nonce += 1


def rank_trnsctions():
    perm_txids = []
    perm_w_txids = []
    dir = "./mempool"
    files = os.listdir(dir)
    info_tx = []
    limit = 4000
    cnt = 0
    for file in files:
        cnt += 1
        if cnt >= limit:
            break
        txdata = extract_json(dir + "/" + file)
        tx_data = json.loads(txdata[0])
        tx = Transaction(
            version=tx_data["version"],
            locktime=tx_data["locktime"],
            vin=[Input(
                txid=vin_data["txid"],
                vout=vin_data["vout"],
                prevout=Prevout(
                    scriptpubkey=vin_data["prevout"]["scriptpubkey"],
                    scriptpubkey_asm=vin_data["prevout"]["scriptpubkey_asm"],
                    scriptpubkey_type=vin_data["prevout"]["scriptpubkey_type"],
                    scriptpubkey_address=vin_data["prevout"]["scriptpubkey_address"],
                    value=vin_data["prevout"]["value"]
                ),
                scriptsig=vin_data["scriptsig"],
                scriptsig_asm=vin_data["scriptsig_asm"],
                witness=vin_data.get("witness", []),
                is_coinbase=vin_data["is_coinbase"],
                sequence=vin_data["sequence"]
            ) for vin_data in tx_data["vin"]],
            vout=[Prevout(
                scriptpubkey=vout_data["scriptpubkey"],
                scriptpubkey_asm=vout_data["scriptpubkey_asm"],
                scriptpubkey_type=vout_data["scriptpubkey_type"],
                value=vout_data["value"],
                scriptpubkey_address=vout_data.get("scriptpubkey_address")
            ) for vout_data in tx_data["vout"]]
        )
        fee = 0
        for vin in tx.vin:
            fee += vin.prevout.value
        for vout in tx.vout:
            fee -= vout.value
        serialized = serialize_transaction(tx)
        sereial_seg = segwit_serialize(tx)
        txID = bytes_rev(sha(sha(serialized))).hex()
        wtxID = bytes_rev(sha(sha(sereial_seg))).hex()
        info_tx.append(TxInfo(txID, wtxID, fee, wit_sz_calc(tx) + len(serialize_transaction(tx)) * 4))

    if info_tx:
        max_fee_per_weight = max(tx.fee / tx.weight for tx in info_tx)
        info_tx.sort(key=lambda x: x.fee / x.weight / max_fee_per_weight, reverse=True)
    permissible_txs = []
    permissible_weight = 3999300
    reward = 0
    for tx in info_tx:
        if permissible_weight >= tx.weight:
            permissible_txs.append(tx)
            permissible_weight -= tx.weight
            perm_txids.append(tx.txid)
            perm_w_txids.append(tx.wtxid)
            reward += tx.fee

    return reward, perm_txids, perm_w_txids


# Weight
def wit_sz_calc(tx):
    if not detect_segwit(tx):
        return 0

    serialized = b""
    is_segwit = detect_segwit(tx)
    if is_segwit:
        serialized += b"\x00\x01"
    if is_segwit:
        for vin in tx.vin:
            witness_count = len(vin.witness)
            serialized += serialize_int(witness_count)
            for witness in vin.witness:
                witness_bytes = bytes.fromhex(witness)
                witnessLen = len(witness_bytes)
                serialized += serialize_int(witnessLen)
                serialized += witness_bytes

    return len(serialized)


# Final Mining
def init_coinbase(net_reward):
    witness_comm = craete_witness_merkrle()
    coinbase_tx = Transaction(
        version=1,
        vin=[
            Input(
                txid="0000000000000000000000000000000000000000000000000000000000000000",
                vout=0xffffffff,
                prevout=Prevout(
                    scriptpubkey="0014df4bf9f3621073202be59ae590f55f42879a21a0",
                    scriptpubkey_asm="0014df4bf9f3621073202be59ae590f55f42879a21a0",
                    scriptpubkey_type="p2pkh",
                    scriptpubkey_address="bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
                    value=net_reward,
                ),
                is_coinbase=True,
                sequence=0xffffffff,
                scriptsig="03951a0604f15ccf5609013803062b9b5a0100072f425443432f20",
                scriptsig_asm="03951a0604f15ccf5609013803062b9b5a0100072f425443432f20",
                witness=["0000000000000000000000000000000000000000000000000000000000000000"],
            )
        ],
        vout=[
            Prevout(
                scriptpubkey="0014df4bf9f3621073202be59ae590f55f42879a21a0",
                scriptpubkey_asm="0014df4bf9f3621073202be59ae590f55f42879a21a0",
                scriptpubkey_type="p2pkh",
                scriptpubkey_address="bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
                value=net_reward,
            ),
            Prevout(
                scriptpubkey="6a24" + "aa21a9ed" + witness_comm,
                scriptpubkey_asm="OP_RETURN" + "OP_PUSHBYTES_36" + "aa21a9ed" + witness_comm,
                scriptpubkey_type="op_return",
                scriptpubkey_address="bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
                value=0,
            ),
        ],
        locktime=0,
    )
    return coinbase_tx


def final_mining():
    net_reward, tx_ids, _ = rank_trnsctions()

    tx_cb = init_coinbase(net_reward)
    serialized_cb_tx = serialize_transaction(tx_cb)

    tx_ids = [bytes_rev(sha(sha(serialized_cb_tx))).hex()] + tx_ids
    mkr = create_mekrle_tree(tx_ids)
    blck_header.merkle_root = mkr.data.hex()
    cb_tx_base = len(serialize_transaction(tx_cb))
    cb_tx_witness = wit_sz_calc(tx_cb)

    if pow(blck_header):
        with open("output.txt", "w") as file:
            serialized_blck_header = serialize_blck_header(blck_header)
            sereial_seg = segwit_serialize(tx_cb)
            file.write(serialized_blck_header.hex() + "\n")
            file.write(sereial_seg.hex() + "\n")
            for tx in tx_ids:
                file.write(tx + "\n")


def main():
    final_mining()


if __name__ == "__main__":
    main()
