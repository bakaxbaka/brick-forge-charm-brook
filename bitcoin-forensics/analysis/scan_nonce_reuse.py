#!/usr/bin/env python3
"""Scan Bitcoin blocks for ECDSA nonce (r) reuse in legacy P2PKH / P2SH signatures."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from coincurve import PrivateKey, PublicKey
from Crypto.Hash import RIPEMD160

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80
OP_CODESEPARATOR = 0xAB
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88

MAGIC = bytes.fromhex("f9beb4d9")
MSG_BLOCK = 2
NODE_NETWORK = 1
PROTOCOL_VERSION = 70015
USER_AGENT = "/btc-nonce-scan:1.0/"

HALVING_HASH_BE = "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"

CALIB_TXIDS = [
    "043ca0530edc0799a78aa35d1bdbe36001398fdb1c2ecc6127d5b099e2f54045",
    "3c474ee8fe1871af08c1a35d7c844619f5a1ffb37c6f5c0c2d45d946492e3ce5",
]

DNS_SEEDS = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoin.jonasschnelli.ch",
]
PREFERRED_PEERS = [
    "15.235.229.33",
    "163.172.147.5",
    "131.188.42.159",
    "172.104.172.142",
]

RESULTS = Path(os.environ.get("RESULTS_DIR", "/results"))
CACHE = Path(os.environ.get("CACHE_DIR", "/workspace/bitcoin-forensics/cache"))
PROGRESS_PATH = RESULTS / "progress.json"
SIGS_PATH = RESULTS / "signatures.jsonl"
REUSE_PATH = RESULTS / "nonce_reuse.jsonl"
KEYS_PATH = RESULTS / "recovered_keys.jsonl"
FAILED_BLOCKS_PATH = RESULTS / "failed_blocks.txt"
MALFORMED_PATH = RESULTS / "malformed_txs.txt"
EXCEPTIONS_PATH = RESULTS / "exceptions.txt"

HTTP_SESSION = requests.Session()
HTTP_SESSION.headers.update({"User-Agent": "btc-nonce-scan/1.0"})
_rate_lock = threading.Lock()
_rate_times: List[float] = []
RATE_PER_SEC = 5.0


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / "blocks").mkdir(parents=True, exist_ok=True)


def dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash160(b: bytes) -> bytes:
    return RIPEMD160.new(sha256(b)).digest()


def encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def encode_push(data: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return b"\x00"
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return bytes([0x4C, n]) + data
    if n <= 65535:
        return bytes([0x4D]) + n.to_bytes(2, "little") + data
    return bytes([0x4E]) + n.to_bytes(4, "little") + data


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos

    def remaining(self) -> int:
        return len(self.d) - self.p

    def u8(self) -> int:
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self) -> int:
        v = int.from_bytes(self.d[self.p : self.p + 2], "little")
        self.p += 2
        return v

    def u32(self) -> int:
        v = int.from_bytes(self.d[self.p : self.p + 4], "little")
        self.p += 4
        return v

    def u64(self) -> int:
        v = int.from_bytes(self.d[self.p : self.p + 8], "little")
        self.p += 8
        return v

    def take(self, n: int) -> bytes:
        if self.p + n > len(self.d):
            raise ValueError("short buffer")
        v = self.d[self.p : self.p + n]
        self.p += n
        return v

    def varint(self) -> int:
        b = self.u8()
        if b < 0xFD:
            return b
        if b == 0xFD:
            return self.u16()
        if b == 0xFE:
            return self.u32()
        return self.u64()

    def varstr(self) -> bytes:
        return self.take(self.varint())


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------
def encode_der(r: int, s: int) -> bytes:
    def enc_int(x: int) -> bytes:
        if x == 0:
            b = b"\x00"
        else:
            b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b

    body = enc_int(r) + enc_int(s)
    if len(body) < 0x80:
        return bytes([0x30, len(body)]) + body
    lb = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0x30, 0x80 | len(lb)]) + lb + body


def parse_der_sig(blob: bytes) -> Optional[Tuple[int, int, int]]:
    """Tolerant DER parse. blob is DER || sighash_type. Returns (r, s, sighash_type)."""
    if blob is None or len(blob) < 9:
        return None
    sighash_type = blob[-1]
    der = blob[:-1]
    try:
        if der[0] != 0x30:
            return None
        pos = 1

        def read_len(p: int) -> Tuple[int, int]:
            lb = der[p]
            p += 1
            if lb & 0x80:
                nlen = lb & 0x7F
                if nlen == 0 or p + nlen > len(der):
                    raise ValueError("bad len")
                ln = int.from_bytes(der[p : p + nlen], "big")
                p += nlen
                return ln, p
            return lb, p

        _total, pos = read_len(pos)
        if der[pos] != 0x02:
            return None
        pos += 1
        rlen, pos = read_len(pos)
        if rlen <= 0 or pos + rlen > len(der):
            return None
        r = int.from_bytes(der[pos : pos + rlen], "big")
        pos += rlen
        if pos >= len(der) or der[pos] != 0x02:
            return None
        pos += 1
        slen, pos = read_len(pos)
        if slen <= 0 or pos + slen > len(der):
            return None
        s = int.from_bytes(der[pos : pos + slen], "big")
        if r <= 0 or s <= 0 or r >= N or s >= N:
            return None
        return r, s, sighash_type
    except Exception:
        return None


def is_pubkey(b: bytes) -> bool:
    if not b:
        return False
    if len(b) == 33 and b[0] in (2, 3):
        return True
    if len(b) == 65 and b[0] == 4:
        return True
    return False


def looks_like_sig(b: bytes) -> bool:
    return bool(b) and len(b) >= 9 and b[0] == 0x30


def p2pkh_script(pubkey: bytes) -> bytes:
    return b"\x76\xa9\x14" + hash160(pubkey) + b"\x88\xac"


def priv_to_pub(d: int, compressed: bool) -> bytes:
    return PrivateKey(d.to_bytes(32, "big")).public_key.format(compressed=compressed)


def verify_ecdsa(pubkey: bytes, z: bytes, r: int, s: int) -> bool:
    try:
        ss = s if s <= (N >> 1) else (N - s)
        der = encode_der(r, ss)
        return PublicKey(pubkey).verify(der, z, hasher=None)
    except Exception:
        return False


def recover_priv(r: int, s1: int, z1: int, s2: int, z2: int, pubkey: bytes) -> Optional[Tuple[int, int]]:
    """Recover (k, d) from two signatures sharing r. Tries s-malleability variants."""
    if s1 == s2 and z1 == z2:
        return None
    compressed = len(pubkey) == 33
    variants = [(s1, s2), (s1, (-s2) % N), ((-s1) % N, s2), ((-s1) % N, (-s2) % N)]
    rinv = pow(r, -1, N)
    for ss1, ss2 in variants:
        denom = (ss1 - ss2) % N
        if denom == 0:
            continue
        k = ((z1 - z2) * pow(denom, -1, N)) % N
        if k == 0:
            continue
        for kk in (k, (-k) % N):
            d = ((ss1 * kk - z1) * rinv) % N
            if d == 0:
                continue
            try:
                pub = priv_to_pub(d, compressed)
            except Exception:
                continue
            if pub == pubkey:
                return kk, d
            if not compressed:
                continue
            try:
                pubu = priv_to_pub(d, False)
            except Exception:
                continue
            if pubu == pubkey:
                return kk, d
    return None


# ---------------------------------------------------------------------------
# Scripts / transactions
# ---------------------------------------------------------------------------
def iter_ops(script: bytes) -> List[Tuple[int, int, int, bytes]]:
    """List of (start, end, opcode, data)."""
    out: List[Tuple[int, int, int, bytes]] = []
    p = 0
    n = len(script)
    try:
        while p < n:
            start = p
            op = script[p]
            p += 1
            data = b""
            if op == 0:
                data = b""
            elif 1 <= op <= 75:
                data = script[p : p + op]
                p += op
            elif op == 0x4C:
                ln = script[p]
                p += 1
                data = script[p : p + ln]
                p += ln
            elif op == 0x4D:
                ln = int.from_bytes(script[p : p + 2], "little")
                p += 2
                data = script[p : p + ln]
                p += ln
            elif op == 0x4E:
                ln = int.from_bytes(script[p : p + 4], "little")
                p += 4
                data = script[p : p + ln]
                p += ln
            if p > n:
                break
            out.append((start, p, op, data))
    except Exception:
        return out
    return out


def parse_pushes(script: bytes) -> List[bytes]:
    pushes: List[bytes] = []
    for _s, _e, op, data in iter_ops(script):
        if op == 0 or 1 <= op <= 75 or op in (0x4C, 0x4D, 0x4E):
            pushes.append(data)
    return pushes


def find_and_delete(script: bytes, needle: bytes) -> bytes:
    if not needle or not script:
        return script
    ops = iter_ops(script)
    if not ops:
        return script
    nops = iter_ops(needle)
    if not nops:
        return script
    nl = len(nops)
    out = bytearray()
    i = 0
    while i < len(ops):
        if i + nl <= len(ops):
            chunk = script[ops[i][0] : ops[i + nl - 1][1]]
            if chunk == needle:
                i += nl
                continue
        out += script[ops[i][0] : ops[i][1]]
        i += 1
    return bytes(out)


def parse_tx(data: bytes, pos: int = 0) -> Tuple[Dict[str, Any], int]:
    r = Reader(data, pos)
    start = r.p
    version = r.u32()
    # Pre-segwit only in this range; still detect marker/flag to skip witness.
    marker_flag = False
    peek = r.d[r.p : r.p + 2] if r.remaining() >= 2 else b""
    if peek == b"\x00\x01":
        r.take(2)
        marker_flag = True
    n_in = r.varint()
    inputs = []
    for _ in range(n_in):
        prev_hash = r.take(32)
        prev_index = r.u32()
        script = r.varstr()
        sequence = r.u32()
        inputs.append(
            {
                "prev_hash": prev_hash,
                "prev_index": prev_index,
                "script": script,
                "sequence": sequence,
                "witness": [],
            }
        )
    n_out = r.varint()
    outputs = []
    for _ in range(n_out):
        value = r.u64()
        script = r.varstr()
        outputs.append({"value": value, "script": script})
    if marker_flag:
        for i in range(n_in):
            n_stack = r.varint()
            stack = [r.varstr() for _ in range(n_stack)]
            inputs[i]["witness"] = stack
    locktime = r.u32()
    raw = data[start:r.p]
    # txid for witness txs is hash of non-witness serialization; we only need
    # pre-segwit here so hashing the raw bytes is correct.
    if marker_flag:
        # strip witness for txid: re-serialize without marker/flag/witness
        raw_nw = serialize_tx_legacy(
            {"version": version, "inputs": inputs, "outputs": outputs, "locktime": locktime}
        )
        txid_le = dsha256(raw_nw)
    else:
        txid_le = dsha256(raw)
    tx = {
        "version": version,
        "inputs": inputs,
        "outputs": outputs,
        "locktime": locktime,
        "raw": raw,
        "txid": txid_le[::-1].hex(),
        "is_coinbase": (n_in == 1 and inputs[0]["prev_hash"] == b"\x00" * 32 and inputs[0]["prev_index"] == 0xFFFFFFFF),
    }
    return tx, r.p


def serialize_tx_legacy(tx: Dict[str, Any]) -> bytes:
    out = bytearray()
    out += tx["version"].to_bytes(4, "little")
    out += encode_varint(len(tx["inputs"]))
    for inp in tx["inputs"]:
        out += inp["prev_hash"]
        out += inp["prev_index"].to_bytes(4, "little")
        sc = inp["script"]
        out += encode_varint(len(sc)) + sc
        out += inp["sequence"].to_bytes(4, "little")
    out += encode_varint(len(tx["outputs"]))
    for o in tx["outputs"]:
        out += o["value"].to_bytes(8, "little")
        out += encode_varint(len(o["script"])) + o["script"]
    out += tx["locktime"].to_bytes(4, "little")
    return bytes(out)


def parse_block(raw: bytes) -> Dict[str, Any]:
    if len(raw) < 80:
        raise ValueError("block too short")
    header = raw[:80]
    block_hash = dsha256(header)[::-1].hex()
    version = int.from_bytes(header[0:4], "little")
    prev = header[4:36][::-1].hex()
    merkle = header[36:68][::-1].hex()
    timestamp = int.from_bytes(header[68:72], "little")
    bits = int.from_bytes(header[72:76], "little")
    nonce = int.from_bytes(header[76:80], "little")
    r = Reader(raw, 80)
    n_tx = r.varint()
    txs = []
    for _ in range(n_tx):
        tx, newp = parse_tx(raw, r.p)
        r.p = newp
        txs.append(tx)
    return {
        "hash": block_hash,
        "version": version,
        "prev": prev,
        "merkle": merkle,
        "time": timestamp,
        "bits": bits,
        "nonce": nonce,
        "txs": txs,
        "header": header,
    }


def signature_hash(tx: Dict[str, Any], input_index: int, script_code: bytes, sighash_type: int) -> bytes:
    n_hash = sighash_type & 0x1F
    anyone = bool(sighash_type & SIGHASH_ANYONECANPAY)
    if input_index >= len(tx["inputs"]):
        return (1).to_bytes(32, "little")
    if n_hash == SIGHASH_SINGLE and input_index >= len(tx["outputs"]):
        return (1).to_bytes(32, "little")

    script_code = find_and_delete(script_code, bytes([OP_CODESEPARATOR]))

    out = bytearray()
    out += tx["version"].to_bytes(4, "little")

    if anyone:
        inp = tx["inputs"][input_index]
        out += encode_varint(1)
        out += inp["prev_hash"]
        out += inp["prev_index"].to_bytes(4, "little")
        out += encode_varint(len(script_code)) + script_code
        out += inp["sequence"].to_bytes(4, "little")
    else:
        out += encode_varint(len(tx["inputs"]))
        for i, inp in enumerate(tx["inputs"]):
            out += inp["prev_hash"]
            out += inp["prev_index"].to_bytes(4, "little")
            sc = script_code if i == input_index else b""
            out += encode_varint(len(sc)) + sc
            seq = inp["sequence"]
            if i != input_index and n_hash in (SIGHASH_NONE, SIGHASH_SINGLE):
                seq = 0
            out += seq.to_bytes(4, "little")

    if n_hash == SIGHASH_NONE:
        out += encode_varint(0)
    elif n_hash == SIGHASH_SINGLE:
        out += encode_varint(input_index + 1)
        for _i in range(input_index):
            out += (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            out += encode_varint(0)
        o = tx["outputs"][input_index]
        out += o["value"].to_bytes(8, "little")
        out += encode_varint(len(o["script"])) + o["script"]
    else:
        out += encode_varint(len(tx["outputs"]))
        for o in tx["outputs"]:
            out += o["value"].to_bytes(8, "little")
            out += encode_varint(len(o["script"])) + o["script"]

    out += tx["locktime"].to_bytes(4, "little")
    out += (sighash_type & 0xFFFFFFFF).to_bytes(4, "little")
    return dsha256(bytes(out))


def extract_redeem_and_pubkeys(pushes: List[bytes]) -> Tuple[Optional[bytes], List[bytes], List[Tuple[int, int, int]]]:
    """Return (redeem_script or None, pubkeys, signatures(r,s,htype))."""
    sigs: List[Tuple[int, int, int]] = []
    pubs: List[bytes] = []
    redeem: Optional[bytes] = None
    for i, p in enumerate(pushes):
        if looks_like_sig(p):
            parsed = parse_der_sig(p)
            if parsed:
                sigs.append(parsed)
        if is_pubkey(p):
            pubs.append(p)
    if pushes:
        last = pushes[-1]
        if last and not is_pubkey(last) and not looks_like_sig(last):
            if last and last[-1] in (OP_CHECKSIG, OP_CHECKMULTISIG, 0xAD, 0xAF):
                redeem = last
            elif any(b in last for b in (OP_CHECKSIG, OP_CHECKMULTISIG)):
                redeem = last
        # P2SH-P2PK: last push is a pubkey used as redeem? uncommon. skip.
    return redeem, pubs, sigs


def script_code_for_input(pushes: List[bytes], redeem: Optional[bytes], pubs: List[bytes]) -> Optional[bytes]:
    if redeem is not None:
        return redeem
    if pubs:
        return p2pkh_script(pubs[0])
    return None


def pubs_from_redeem(redeem: bytes) -> List[bytes]:
    pubs = []
    for _s, _e, op, data in iter_ops(redeem):
        if is_pubkey(data):
            pubs.append(data)
    return pubs


# ---------------------------------------------------------------------------
# Progress / logging
# ---------------------------------------------------------------------------
def atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def default_progress(start: int) -> Dict[str, Any]:
    return {
        "last_completed_height": start - 1,
        "blocks_scanned": 0,
        "txs_scanned": 0,
        "inputs_scanned": 0,
        "valid_sigs": 0,
        "invalid_sigs": 0,
        "invalid_by_reason": {},
        "reuse_groups": 0,
        "keys_recovered": 0,
        "unique_pubkeys": 0,
        "pr_groups": 0,
        "failed_blocks": 0,
        "started_at": utcnow(),
        "updated_at": utcnow(),
        "mode": "api",
        "calibration": "pending",
    }


def load_progress(start: int) -> Dict[str, Any]:
    if PROGRESS_PATH.exists():
        try:
            with open(PROGRESS_PATH) as f:
                p = json.load(f)
            for k, v in default_progress(start).items():
                p.setdefault(k, v)
            return p
        except Exception:
            pass
    p = default_progress(start)
    atomic_write_json(PROGRESS_PATH, p)
    return p


def bump_reason(progress: Dict[str, Any], reason: str) -> None:
    d = progress.setdefault("invalid_by_reason", {})
    d[reason] = d.get(reason, 0) + 1
    progress["invalid_sigs"] = progress.get("invalid_sigs", 0) + 1


def append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(line)
        if not line.endswith("\n"):
            f.write("\n")


def heartbeat(height: int, progress: Dict[str, Any], t0: float) -> None:
    elapsed = int(time.time() - t0)
    line = (
        f"[HEARTBEAT] height={height} done={progress.get('blocks_scanned', 0)} "
        f"reuse={progress.get('reuse_groups', 0)} elapsed={elapsed}s"
    )
    print(line, flush=True)


# ---------------------------------------------------------------------------
# HTTP (API mode) + rate limit
# ---------------------------------------------------------------------------
def rate_wait() -> None:
    with _rate_lock:
        now = time.time()
        while _rate_times and now - _rate_times[0] > 1.0:
            _rate_times.pop(0)
        if len(_rate_times) >= RATE_PER_SEC:
            sleep = 1.0 - (now - _rate_times[0]) + 0.02
            if sleep > 0:
                time.sleep(sleep)
            now = time.time()
            while _rate_times and now - _rate_times[0] > 1.0:
                _rate_times.pop(0)
        _rate_times.append(time.time())


def http_get(url: str, binary: bool = False, timeout: int = 30) -> Any:
    for attempt in range(12):
        rate_wait()
        try:
            r = HTTP_SESSION.get(url, timeout=timeout)
            if r.status_code == 429:
                time.sleep(5)
                continue
            if r.status_code >= 500:
                time.sleep(min(2 ** attempt, 16))
                continue
            r.raise_for_status()
            return r.content if binary else r.text
        except Exception:
            if attempt == 11:
                raise
            time.sleep(min(2 ** attempt, 16))
    raise RuntimeError(f"http_get failed {url}")


def cache_path_for_block(height: int) -> Path:
    return CACHE / "blocks" / f"{height}.bin"


def fetch_tx_hex(txid: str) -> str:
    cp = CACHE / f"tx_{txid}.hex"
    if cp.exists():
        return cp.read_text().strip()
    urls = [
        f"https://blockchain.info/rawtx/{txid}?format=hex",
        f"https://mempool.space/api/tx/{txid}/hex",
        f"https://blockstream.info/api/tx/{txid}/hex",
    ]
    last = None
    for url in urls:
        try:
            text = http_get(url).strip()
            if all(c in "0123456789abcdefABCDEF" for c in text) and len(text) >= 20:
                cp.write_text(text)
                return text
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"could not fetch tx {txid}: {last}")


def fetch_block_hex_http(block_hash: str) -> bytes:
    urls = [
        f"https://blockchain.info/rawblock/{block_hash}?format=hex",
        f"https://mempool.space/api/block/{block_hash}/raw",
        f"https://blockstream.info/api/block/{block_hash}/raw",
    ]
    last = None
    # blockchain.info hex first
    try:
        text = http_get(urls[0])
        text = text.strip()
        if all(c in "0123456789abcdefABCDEF" for c in text) and len(text) >= 160:
            return bytes.fromhex(text)
    except Exception as e:
        last = e
    for url in urls[1:]:
        try:
            raw = http_get(url, binary=True)
            if isinstance(raw, str):
                raw = raw.encode()
            if len(raw) >= 80:
                return raw
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"could not fetch block {block_hash}: {last}")


def fetch_hash_http(height: int) -> str:
    cp = CACHE / f"hash_{height}.txt"
    if cp.exists():
        return cp.read_text().strip()
    urls = [
        f"https://blockchain.info/block-height/{height}?format=json",
        f"https://mempool.space/api/block-height/{height}",
        f"https://blockstream.info/api/block-height/{height}",
    ]
    last = None
    # blockchain.info JSON is heavy; still works
    try:
        text = http_get(urls[0], timeout=60)
        data = json.loads(text)
        h = data["blocks"][0]["hash"]
        cp.write_text(h)
        return h
    except Exception as e:
        last = e
    for url in urls[1:]:
        try:
            h = http_get(url).strip().strip('"')
            if len(h) == 64:
                cp.write_text(h)
                return h
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"could not fetch hash for {height}: {last}")


# ---------------------------------------------------------------------------
# Bitcoin P2P
# ---------------------------------------------------------------------------
def mkmsg(cmd: str, payload: bytes = b"") -> bytes:
    c = cmd.encode().ljust(12, b"\x00")
    return MAGIC + c + len(payload).to_bytes(4, "little") + dsha256(payload)[:4] + payload


def ser_netaddr(services: int, ip: str, port: int) -> bytes:
    out = services.to_bytes(8, "little")
    try:
        packed = socket.inet_aton(ip)
    except OSError:
        packed = socket.inet_aton("0.0.0.0")
    out += bytes.fromhex("00000000000000000000ffff") + packed
    out += port.to_bytes(2, "big")
    return out


def ser_varstr(s: str) -> bytes:
    b = s.encode()
    return encode_varint(len(b)) + b


class BitcoinPeer:
    def __init__(self, ip: str, port: int = 8333, timeout: int = 20):
        self.ip = ip
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.buf = b""
        self.services = 0
        self.timeout = timeout
        self.lock = threading.Lock()

    def connect(self) -> None:
        s = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        self.sock = s
        payload = b""
        payload += (70016).to_bytes(4, "little")
        payload += (NODE_NETWORK).to_bytes(8, "little")
        payload += int(time.time()).to_bytes(8, "little")
        payload += ser_netaddr(NODE_NETWORK, self.ip, self.port)
        payload += ser_netaddr(NODE_NETWORK, "0.0.0.0", 0)
        payload += os.urandom(8)
        payload += ser_varstr("/Satoshi:22.0.0/")
        payload += (220000).to_bytes(4, "little")
        payload += b"\x01"
        self.send_raw(mkmsg("version", payload))
        got = set()
        deadline = time.time() + 25
        while time.time() < deadline and not {"version", "verack"} <= got:
            cmd, pl = self.recv_msg(deadline=deadline)
            if cmd is None:
                continue
            if cmd == "_closed":
                raise RuntimeError("peer closed during handshake")
            if cmd == "version":
                if len(pl) >= 12:
                    self.services = int.from_bytes(pl[4:12], "little")
                self.send_raw(mkmsg("verack"))
                got.add("version")
            elif cmd == "verack":
                got.add("verack")
            else:
                self.keep_alive(cmd, pl)
        if not {"version", "verack"} <= got:
            raise RuntimeError("handshake failed")

    def send_raw(self, data: bytes) -> None:
        assert self.sock is not None
        self.sock.sendall(data)

    def send(self, cmd: str, payload: bytes = b"") -> None:
        self.send_raw(mkmsg(cmd, payload))

    def keep_alive(self, cmd: str, pl: bytes) -> None:
        try:
            if cmd == "ping":
                self.send("pong", pl)
            elif cmd == "getheaders":
                self.send("headers", encode_varint(0))
            elif cmd == "getdata":
                self.send("notfound", pl)
            elif cmd == "getaddr":
                self.send("addr", encode_varint(0))
        except Exception:
            pass

    def recv_msg(self, deadline: Optional[float] = None) -> Tuple[Optional[str], bytes]:
        assert self.sock is not None
        while True:
            if len(self.buf) >= 24:
                if self.buf[:4] != MAGIC:
                    idx = self.buf.find(MAGIC)
                    if idx == -1:
                        self.buf = self.buf[-3:]
                    else:
                        self.buf = self.buf[idx:]
                        continue
                else:
                    cmd = self.buf[4:16].split(b"\x00", 1)[0].decode("latin1")
                    ln = int.from_bytes(self.buf[16:20], "little")
                    if ln > 8_000_000:
                        raise RuntimeError(f"oversized message {cmd} {ln}")
                    if len(self.buf) >= 24 + ln:
                        payload = self.buf[24 : 24 + ln]
                        self.buf = self.buf[24 + ln :]
                        return cmd, payload
            remaining = None
            if deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None, b""
            self.sock.settimeout(max(0.5, remaining if remaining is not None else self.timeout))
            try:
                chunk = self.sock.recv(262144)
            except socket.timeout:
                return None, b""
            if not chunk:
                return "_closed", b""
            self.buf += chunk

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None

    def is_full(self) -> bool:
        return bool(self.services & NODE_NETWORK)



def dns_peers(limit: int = 30) -> List[str]:
    ips: List[str] = list(PREFERRED_PEERS)
    for seed in DNS_SEEDS:
        try:
            infos = socket.getaddrinfo(seed, 8333, socket.AF_INET, socket.SOCK_STREAM)
            for inf in infos:
                ip = inf[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            continue
        if len(ips) >= limit:
            break
    return ips[:limit]


def connect_full_peer(ips: List[str]) -> BitcoinPeer:
    last = None
    for ip in ips:
        try:
            p = BitcoinPeer(ip)
            p.connect()
            if p.is_full() or True:
                # some peers leave services=0 in our parse; still try
                print(f"[p2p] connected {ip} services={p.services}", flush=True)
                return p
            p.close()
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"no p2p peer: {last}")


def getheaders_payload(locator: bytes, hash_stop: bytes = b"\x00" * 32) -> bytes:
    out = PROTOCOL_VERSION.to_bytes(4, "little")
    out += encode_varint(1)
    out += locator
    out += hash_stop
    return out


def parse_headers_payload(payload: bytes) -> List[bytes]:
    r = Reader(payload)
    n = r.varint()
    headers = []
    for _ in range(n):
        h = r.take(80)
        _txc = r.varint()
        headers.append(h)
    return headers


def header_hash_be(header: bytes) -> str:
    return dsha256(header)[::-1].hex()


def header_hash_le(header: bytes) -> bytes:
    return dsha256(header)


def sync_headers(start_height: int, end_height: int) -> List[Tuple[int, str, int]]:
    """Return list of (height, hash_be, time) covering start..end inclusive."""
    cache_file = CACHE / "headers.json"
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text())
            if (
                data
                and data[0][0] <= start_height
                and data[-1][0] >= end_height
                and data[0][1]
            ):
                sliced = [tuple(x) for x in data if start_height <= x[0] <= end_height]
                if len(sliced) == (end_height - start_height + 1):
                    print(f"[p2p] loaded {len(sliced)} headers from cache", flush=True)
                    return sliced  # type: ignore
        except Exception:
            pass

    locator = bytes.fromhex(HALVING_HASH_BE)[::-1]
    results: Dict[int, Tuple[str, int]] = {210000: (HALVING_HASH_BE, 0)}
    height = 210000
    current_locator = locator
    ips = dns_peers(80)
    print(f"[p2p] {len(ips)} dns peers for header sync", flush=True)
    last_err: Optional[Exception] = None
    for ip in ips:
        if height >= end_height:
            break
        peer = None
        try:
            peer = BitcoinPeer(ip, timeout=25)
            peer.connect()
            print(f"[p2p] headers peer {ip} services={peer.services}", flush=True)
            idle = 0
            while height < end_height and idle < 3:
                peer.send("getheaders", getheaders_payload(current_locator))
                got_headers = None
                deadline = time.time() + 20
                while time.time() < deadline:
                    cmd, pl = peer.recv_msg(deadline=deadline)
                    if cmd is None:
                        continue
                    if cmd == "_closed":
                        raise RuntimeError("peer closed")
                    if cmd == "headers":
                        got_headers = parse_headers_payload(pl)
                        break
                    peer.keep_alive(cmd, pl)
                if not got_headers:
                    idle += 1
                    print(f"[p2p] no headers from {ip} idle={idle}", flush=True)
                    continue
                idle = 0
                for hdr in got_headers:
                    height += 1
                    hbe = header_hash_be(hdr)
                    ts = int.from_bytes(hdr[68:72], "little")
                    results[height] = (hbe, ts)
                    current_locator = header_hash_le(hdr)
                    if height >= end_height:
                        break
                print(f"[p2p] headers through {height} (+{len(got_headers)})", flush=True)
        except Exception as e:
            last_err = e
            print(f"[p2p] peer {ip} failed: {e}", flush=True)
        finally:
            if peer:
                peer.close()

    if start_height < 210000:
        raise RuntimeError("header sync assumes start >= 210000")
    out = []
    missing = []
    for h in range(start_height, end_height + 1):
        if h not in results:
            missing.append(h)
        else:
            out.append((h, results[h][0], results[h][1]))
    if missing:
        raise RuntimeError(f"missing {len(missing)} headers e.g. {missing[:5]} last_err={last_err}")
    cache_file.write_text(json.dumps(out))
    return out


def getdata_payload(hashes_le: List[bytes]) -> bytes:
    out = encode_varint(len(hashes_le))
    for h in hashes_le:
        out += MSG_BLOCK.to_bytes(4, "little") + h
    return out


def p2p_fetch_blocks(wanted: List[Tuple[int, str]], progress_cb=None) -> int:
    """Download missing blocks into cache. Returns count downloaded."""
    missing = [(h, hb) for h, hb in wanted if not cache_path_for_block(h).exists()]
    if not missing:
        return 0
    print(f"[p2p] {len(missing)} blocks missing from cache", flush=True)
    ips = dns_peers(40)
    downloaded = 0
    batch_size = 64
    i = 0
    peer: Optional[BitcoinPeer] = None
    peer_idx = 0

    def reconnect() -> BitcoinPeer:
        nonlocal peer_idx
        last = None
        for _ in range(len(ips)):
            ip = ips[peer_idx % len(ips)]
            peer_idx += 1
            try:
                p = BitcoinPeer(ip, timeout=30)
                p.connect()
                print(f"[p2p] download peer {ip}", flush=True)
                return p
            except Exception as e:
                last = e
                continue
        raise RuntimeError(f"reconnect failed: {last}")

    try:
        peer = reconnect()
        empty_tries = 0
        while i < len(missing):
            batch = missing[i : i + batch_size]
            still = [(h, hb) for h, hb in batch if not cache_path_for_block(h).exists()]
            if not still:
                i += batch_size
                continue
            inv = [bytes.fromhex(hb)[::-1] for h, hb in still]
            expect = {hb: h for h, hb in still}
            try:
                peer.send("getdata", getdata_payload(inv))
            except Exception:
                try:
                    peer.close()
                except Exception:
                    pass
                peer = reconnect()
                continue
            got = 0
            deadline = time.time() + 90
            while got < len(still) and time.time() < deadline:
                try:
                    cmd, pl = peer.recv_msg(deadline=deadline)
                except Exception:
                    break
                if cmd is None:
                    continue
                if cmd == "_closed":
                    break
                if cmd == "block":
                    if len(pl) < 80:
                        continue
                    hbe = header_hash_be(pl[:80])
                    if hbe in expect:
                        height = expect[hbe]
                        path = cache_path_for_block(height)
                        tmp = path.with_suffix(".tmp")
                        tmp.write_bytes(pl)
                        os.replace(tmp, path)
                        downloaded += 1
                        got += 1
                        if progress_cb:
                            progress_cb(height, downloaded, len(missing))
                elif cmd == "notfound":
                    print(f"[p2p] notfound from {peer.ip}, rotating", flush=True)
                    break
                else:
                    peer.keep_alive(cmd, pl)
            if got == 0:
                empty_tries += 1
                try:
                    peer.close()
                except Exception:
                    pass
                if empty_tries >= 12:
                    append_line(FAILED_BLOCKS_PATH, f"{still[0][0]} p2p-unavailable")
                    i += 1
                    empty_tries = 0
                peer = reconnect()
                continue
            empty_tries = 0
            while i < len(missing) and cache_path_for_block(missing[i][0]).exists():
                i += 1
            if downloaded % 128 == 0:
                print(f"[p2p] downloaded {downloaded}/{len(missing)} next={missing[i][0] if i < len(missing) else 'done'}", flush=True)
    finally:
        if peer:
            peer.close()
    return downloaded


# ---------------------------------------------------------------------------
# Extraction / grouping
# ---------------------------------------------------------------------------
class ScanState:
    def __init__(self):
        self.first: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.groups_reused: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self.pubkeys: set = set()
        self.recovered_keys: set = set()
        self.lock = threading.Lock()
        self.sig_f = open(SIGS_PATH, "a")
        self.reuse_f = open(REUSE_PATH, "a")
        self.keys_f = open(KEYS_PATH, "a")
        self.wlock = threading.Lock()

    def close(self) -> None:
        for f in (self.sig_f, self.reuse_f, self.keys_f):
            try:
                f.flush()
                f.close()
            except Exception:
                pass

    def replay_jsonl(self) -> None:
        if not SIGS_PATH.exists():
            return
        n = 0
        with open(SIGS_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                key = (rec["pubkey_hex"], rec["r"])
                self.pubkeys.add(rec["pubkey_hex"])
                if key not in self.first:
                    self.first[key] = rec
                else:
                    self.groups_reused.setdefault(key, [self.first[key]]).append(rec)
                n += 1
                if n % 200000 == 0:
                    print(f"[resume] replayed {n} signatures", flush=True)
        print(f"[resume] replayed {n} signatures, groups={len(self.first)} reused={len(self.groups_reused)}", flush=True)

    def add_sig(self, rec: Dict[str, Any], progress: Dict[str, Any]) -> None:
        key = (rec["pubkey_hex"], rec["r"])
        self.pubkeys.add(rec["pubkey_hex"])
        with self.wlock:
            self.sig_f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        if key not in self.first:
            self.first[key] = rec
            return
        # reuse
        prev = self.first[key]
        lst = self.groups_reused.setdefault(key, [prev])
        lst.append(rec)
        if len(lst) == 2:
            progress["reuse_groups"] = progress.get("reuse_groups", 0) + 1
        r = int(rec["r"], 16)
        s1 = int(prev["s"], 16)
        z1 = int(prev["z"], 16)
        s2 = int(rec["s"], 16)
        z2 = int(rec["z"], 16)
        pk = bytes.fromhex(rec["pubkey_hex"])
        recovered = recover_priv(r, s1, z1, s2, z2, pk)
        reuse_rec = {
            "pubkey_hex": rec["pubkey_hex"],
            "r": rec["r"],
            "members": [
                {
                    "txid": prev["txid"],
                    "input_index": prev["input_index"],
                    "block_height": prev["block_height"],
                    "s": prev["s"],
                    "z": prev["z"],
                    "sighash_type": prev["sighash_type"],
                },
                {
                    "txid": rec["txid"],
                    "input_index": rec["input_index"],
                    "block_height": rec["block_height"],
                    "s": rec["s"],
                    "z": rec["z"],
                    "sighash_type": rec["sighash_type"],
                },
            ],
            "recovered": recovered is not None,
        }
        if recovered:
            k, d = recovered
            reuse_rec["k"] = hex(k)[2:].zfill(64)
            reuse_rec["d"] = hex(d)[2:].zfill(64)
            if d not in self.recovered_keys:
                self.recovered_keys.add(d)
                progress["keys_recovered"] = progress.get("keys_recovered", 0) + 1
                compressed = len(pk) == 33
                wif = priv_to_wif(d, compressed)
                key_rec = {
                    "pubkey_hex": rec["pubkey_hex"],
                    "d": hex(d)[2:].zfill(64),
                    "k": hex(k)[2:].zfill(64),
                    "wif": wif,
                    "r": rec["r"],
                    "txid_a": prev["txid"],
                    "txid_b": rec["txid"],
                    "block_a": prev["block_height"],
                    "block_b": rec["block_height"],
                    "verified": True,
                }
                with self.wlock:
                    self.keys_f.write(json.dumps(key_rec, separators=(",", ":")) + "\n")
                    self.keys_f.flush()
        with self.wlock:
            self.reuse_f.write(json.dumps(reuse_rec, separators=(",", ":")) + "\n")
            self.reuse_f.flush()


def priv_to_wif(d: int, compressed: bool) -> str:
    payload = b"\x80" + d.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    checksum = dsha256(payload)[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(payload + checksum, "big")
    chars = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(alphabet[rem])
    pad = 0
    for b in payload + checksum:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(chars or ["1"]))


def process_tx(tx: Dict[str, Any], height: int, block_time: int, state: ScanState, progress: Dict[str, Any]) -> None:
    if tx["is_coinbase"]:
        return
    for idx, inp in enumerate(tx["inputs"]):
        progress["inputs_scanned"] = progress.get("inputs_scanned", 0) + 1
        try:
            script = inp["script"]
            pushes = parse_pushes(script)
            if not pushes:
                bump_reason(progress, "empty_scriptsig")
                continue
            redeem, pubs, sigs = extract_redeem_and_pubkeys(pushes)
            if not sigs:
                bump_reason(progress, "no_der_sig")
                continue
            if redeem:
                pubs = list(pubs) + [p for p in pubs_from_redeem(redeem) if p not in pubs]
            script_code = script_code_for_input(pushes, redeem, pubs)
            if script_code is None:
                bump_reason(progress, "no_scriptcode")
                continue
            if not pubs:
                bump_reason(progress, "no_pubkey")
                continue
            raw_sigs = [p for p in pushes if looks_like_sig(p)]
            for si, (r, s, htype) in enumerate(sigs):
                sc = script_code
                if si < len(raw_sigs):
                    sc = find_and_delete(script_code, encode_push(raw_sigs[si]))
                z_bytes = signature_hash(tx, idx, sc, htype)
                z_int = int.from_bytes(z_bytes, "big")
                matched = None
                for pk in pubs:
                    if verify_ecdsa(pk, z_bytes, r, s):
                        matched = pk
                        break
                if matched is None:
                    bump_reason(progress, "verify_fail")
                    continue
                progress["valid_sigs"] = progress.get("valid_sigs", 0) + 1
                rec = {
                    "pubkey_hex": matched.hex(),
                    "r": hex(r)[2:].zfill(64),
                    "s": hex(s)[2:].zfill(64),
                    "z": hex(z_int)[2:].zfill(64),
                    "sighash_type": htype,
                    "txid": tx["txid"],
                    "input_index": idx,
                    "block_height": height,
                    "block_time": block_time,
                }
                state.add_sig(rec, progress)
        except Exception:
            append_line(
                MALFORMED_PATH,
                f"{tx.get('txid','?')}:{idx} height={height} {traceback.format_exc().splitlines()[-1]}",
            )


def process_block_raw(raw: bytes, height: int, state: ScanState, progress: Dict[str, Any]) -> None:
    block = parse_block(raw)
    block_time = block["time"]
    for tx in block["txs"]:
        progress["txs_scanned"] = progress.get("txs_scanned", 0) + 1
        try:
            process_tx(tx, height, block_time, state, progress)
        except Exception:
            append_line(EXCEPTIONS_PATH, f"tx {tx.get('txid','?')} h={height}\n{traceback.format_exc()}")


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------
def calibrate() -> None:
    print("[calibrate] fetching reference transactions", flush=True)
    results = []
    for txid in CALIB_TXIDS:
        hex_str = fetch_tx_hex(txid)
        raw = bytes.fromhex(hex_str)
        tx, _ = parse_tx(raw, 0)
        assert tx["txid"] == txid, f"txid mismatch {tx['txid']} != {txid}"
        per_input = []
        for idx, inp in enumerate(tx["inputs"]):
            pushes = parse_pushes(inp["script"])
            redeem, pubs, sigs = extract_redeem_and_pubkeys(pushes)
            if not sigs or not pubs:
                raise RuntimeError(f"{txid}:{idx} missing sig/pubkey")
            script_code = p2pkh_script(pubs[0])
            raw_sigs = [p for p in pushes if looks_like_sig(p)]
            r, s, htype = sigs[0]
            sc = find_and_delete(script_code, encode_push(raw_sigs[0])) if raw_sigs else script_code
            z_bytes = signature_hash(tx, idx, sc, htype)
            ok = verify_ecdsa(pubs[0], z_bytes, r, s)
            if not ok:
                # try without FindAndDelete of sig
                z2 = signature_hash(tx, idx, script_code, htype)
                ok = verify_ecdsa(pubs[0], z2, r, s)
                z_bytes = z2
            if not ok:
                raise RuntimeError(f"calibration verify failed {txid} input {idx}")
            per_input.append(
                {
                    "r": r,
                    "s": s,
                    "z": int.from_bytes(z_bytes, "big"),
                    "htype": htype,
                    "pk": pubs[0].hex(),
                    "ok": ok,
                }
            )
            print(
                f"[calibrate] {txid[:12]}… vin={idx} der=ok verify=ok sighash={z_bytes.hex()} htype={htype:#x}",
                flush=True,
            )
        # nonce reuse inside the tx?
        by_r = defaultdict(list)
        for i, p in enumerate(per_input):
            by_r[p["r"]].append((i, p))
        recovered_any = False
        for r, members in by_r.items():
            if len(members) < 2:
                continue
            (_i1, a), (_i2, b) = members[0], members[1]
            rec = recover_priv(r, a["s"], a["z"], b["s"], b["z"], bytes.fromhex(a["pk"]))
            if not rec:
                raise RuntimeError(f"calibration recovery failed for {txid} r={hex(r)}")
            k, d = rec
            pub = priv_to_pub(d, True).hex()
            if pub != a["pk"] and priv_to_pub(d, False).hex() != a["pk"]:
                raise RuntimeError("recovered d does not match pubkey")
            print(f"[calibrate] recovered d from {txid[:12]}… d={hex(d)[2:].zfill(64)}", flush=True)
            recovered_any = True
        if not recovered_any:
            raise RuntimeError(f"expected r-reuse inside {txid}")
        results.append(txid)
    print("[calibrate] PASS", flush=True)


# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------
def finalize(progress: Dict[str, Any], t0: float, output_json: Path) -> None:
    reuse = []
    if REUSE_PATH.exists():
        with open(REUSE_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        reuse.append(json.loads(line))
                    except Exception:
                        pass
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps({"count": len(reuse), "groups": reuse}, indent=2))

    csv_path = RESULTS / "recovered_keys.csv"
    rows = []
    if KEYS_PATH.exists():
        with open(KEYS_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pubkey_hex", "d", "k", "wif", "r", "txid_a", "txid_b", "block_a", "block_b", "verified"])
        for rec in rows:
            w.writerow(
                [
                    rec.get("pubkey_hex", ""),
                    rec.get("d", ""),
                    rec.get("k", ""),
                    rec.get("wif", ""),
                    rec.get("r", ""),
                    rec.get("txid_a", ""),
                    rec.get("txid_b", ""),
                    rec.get("block_a", ""),
                    rec.get("block_b", ""),
                    rec.get("verified", ""),
                ]
            )

    elapsed = int(time.time() - t0)
    failed = 0
    if FAILED_BLOCKS_PATH.exists():
        failed = sum(1 for _ in open(FAILED_BLOCKS_PATH))
    summary = f"""# ECDSA nonce-reuse scan summary

- **Range:** blocks {progress.get('range_start', 210000)}–{progress.get('range_end', 220000)} (inclusive)
- **Mode:** {progress.get('mode', 'api')} (disk < 700 GB and/or no docker — no full bitcoind)
- **Blocks scanned:** {progress.get('blocks_scanned', 0)}
- **Transactions scanned:** {progress.get('txs_scanned', 0)}
- **Inputs scanned:** {progress.get('inputs_scanned', 0)}
- **Valid signatures:** {progress.get('valid_sigs', 0)}
- **Invalid signatures by reason:** `{json.dumps(progress.get('invalid_by_reason', {}))}`
- **Unique pubkeys:** {len(getattr(finalize, 'pubkeys', set())) or progress.get('unique_pubkeys', 0)}
- **(pubkey, r) groups:** {progress.get('pr_groups', 0)}
- **Reused groups:** {progress.get('reuse_groups', 0)}
- **Keys recovered:** {progress.get('keys_recovered', 0)}
- **Failed blocks:** {failed}
- **Elapsed time:** {elapsed}s ({elapsed/3600:.2f} h)
- **Started:** {progress.get('started_at')}
- **Finished:** {utcnow()}

## Reuse found?

"""
    if progress.get("keys_recovered", 0) == 0 and progress.get("reuse_groups", 0) == 0:
        summary += (
            "No ECDSA nonce reuse was found in this block range, and no private keys were recovered. "
            "This is expected for blocks 210,000–220,000: the Android SecureRandom bug that produced "
            "widespread k-reuse in Bitcoin wallets postdates height 220,000 (it surfaced around August 2013, "
            "near blocks ~250,000+).\n"
        )
    else:
        summary += (
            f"YES — {progress.get('reuse_groups', 0)} reused (pubkey, r) groups, "
            f"{progress.get('keys_recovered', 0)} private keys recovered. "
            "See `/results/nonce_reuse.json` and `/results/recovered_keys.csv`.\n"
        )
        summary += "\nDo not broadcast, move, or spend anything. Keys are stored only on local disk.\n"
    (RESULTS / "summary.md").write_text(summary)
    print(summary, flush=True)
    nonce_csv = RESULTS / "nonce_reuse.csv"
    with open(nonce_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pubkey_hex", "r", "txid_a", "txid_b", "block_a", "block_b", "recovered", "d"])
        for g in reuse[:]:
            mem = g.get("members") or []
            a = mem[0] if mem else {}
            b = mem[1] if len(mem) > 1 else {}
            w.writerow(
                [
                    g.get("pubkey_hex", ""),
                    g.get("r", ""),
                    a.get("txid", ""),
                    b.get("txid", ""),
                    a.get("block_height", ""),
                    b.get("block_height", ""),
                    g.get("recovered", ""),
                    g.get("d", ""),
                ]
            )
    print("First 20 rows of nonce_reuse.csv:", flush=True)
    with open(nonce_csv) as f:
        for i, line in enumerate(f):
            if i > 20:
                break
            print(line.rstrip(), flush=True)
    if not reuse:
        print(
            "No reuse rows. Expected for this range (Android SecureRandom bug postdates 220,000).",
            flush=True,
        )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def get_block_raw(height: int, block_hash: str) -> bytes:
    path = cache_path_for_block(height)
    if path.exists() and path.stat().st_size >= 80:
        return path.read_bytes()
    try:
        p2p_fetch_blocks([(height, block_hash)])
    except Exception as e:
        append_line(EXCEPTIONS_PATH, f"single-fetch {height} {e}")
    if path.exists() and path.stat().st_size >= 80:
        return path.read_bytes()
    last = None
    for attempt, delay in enumerate((1, 2, 4, 8, 16)):
        try:
            raw = fetch_block_hex_http(block_hash)
            if len(raw) >= 80:
                tmp = path.with_suffix(".tmp")
                tmp.write_bytes(raw)
                os.replace(tmp, path)
                return raw
        except Exception as e:
            last = e
            time.sleep(delay)
    raise RuntimeError(f"block {height} {block_hash} failed: {last}")


def load_header_map(start: int, end: int) -> List[Tuple[int, str, int]]:
    last = None
    for attempt in range(4):
        try:
            return sync_headers(start, end)
        except Exception as e:
            last = e
            print(f"[p2p] header sync attempt {attempt+1} failed: {e}", flush=True)
            time.sleep(2)
    raise RuntimeError(f"header sync failed after retries: {last}")


def run_scan(start: int, end: int, output: Path) -> None:
    ensure_dirs()
    progress = load_progress(start)
    progress["range_start"] = start
    progress["range_end"] = end
    t0 = time.time()
    if progress.get("scan_t0"):
        t0 = float(progress["scan_t0"])
    else:
        progress["scan_t0"] = t0

    # Calibration is mandatory before first real block
    if progress.get("calibration") != "pass":
        calibrate()
        progress["calibration"] = "pass"
        atomic_write_json(PROGRESS_PATH, progress)

    last = progress.get("last_completed_height", start - 1)
    if last >= start:
        print(f"Resuming from height {last + 1}", flush=True)
    if last >= end:
        print("[scan] already complete", flush=True)
        # still finalize
        st = ScanState()
        try:
            st.replay_jsonl()
            progress["unique_pubkeys"] = len(st.pubkeys)
            progress["pr_groups"] = len(st.first)
            finalize.pubkeys = st.pubkeys  # type: ignore
        finally:
            st.close()
        finalize(progress, t0, output)
        return

    print("[scan] syncing headers", flush=True)
    try:
        headers = load_header_map(start, end)
        progress["mode"] = "p2p+api"
    except Exception:
        headers = load_header_map(start, end)
        progress["mode"] = "api"
    atomic_write_json(PROGRESS_PATH, progress)

    hash_by_h = {h: (hb, ts) for h, hb, ts in headers}

    # Opportunistic P2P prefetch of upcoming blocks in a background thread
    def prefetcher():
        try:
            upcoming = []
            for h in range(max(start, last + 1), end + 1):
                hb, _ts = hash_by_h.get(h, ("", 0))
                if hb:
                    upcoming.append((h, hb))
            p2p_fetch_blocks(upcoming)
        except Exception:
            append_line(EXCEPTIONS_PATH, f"prefetch\n{traceback.format_exc()}")
            print("[p2p] prefetch ended; HTTP fallback will fill gaps", flush=True)

    th = threading.Thread(target=prefetcher, name="p2p-prefetch", daemon=True)
    th.start()

    state = ScanState()
    try:
        if SIGS_PATH.exists() and last >= start:
            state.replay_jsonl()
        for height in range(last + 1, end + 1):
            try:
                hb, ts = hash_by_h.get(height, ("", 0))
                if not hb:
                    hb = fetch_hash_http(height)
                    hash_by_h[height] = (hb, ts)
                # wait a moment if prefetch is filling this block
                path = cache_path_for_block(height)
                if not path.exists():
                    for _w in range(120):
                        if path.exists() and path.stat().st_size >= 80:
                            break
                        time.sleep(0.5)
                raw = get_block_raw(height, hb)
                process_block_raw(raw, height, state, progress)
                progress["blocks_scanned"] = progress.get("blocks_scanned", 0) + 1
                progress["last_completed_height"] = height
                progress["updated_at"] = utcnow()
                progress["unique_pubkeys"] = len(state.pubkeys)
                progress["pr_groups"] = len(state.first)
                if height % 10 == 0:
                    with state.wlock:
                        state.sig_f.flush()
                    atomic_write_json(PROGRESS_PATH, progress)
                heartbeat(height, progress, t0)
                if height % 100 == 0:
                    print(
                        f"[summary] height={height} txs={progress['txs_scanned']} "
                        f"inputs={progress['inputs_scanned']} valid={progress['valid_sigs']} "
                        f"reuse={progress['reuse_groups']} keys={progress['keys_recovered']}",
                        flush=True,
                    )
            except Exception:
                append_line(EXCEPTIONS_PATH, f"block {height}\n{traceback.format_exc()}")
                append_line(FAILED_BLOCKS_PATH, str(height))
                progress["failed_blocks"] = progress.get("failed_blocks", 0) + 1
                progress["last_completed_height"] = height
                progress["updated_at"] = utcnow()
                atomic_write_json(PROGRESS_PATH, progress)
                heartbeat(height, progress, t0)
                continue
        with state.wlock:
            state.sig_f.flush()
            state.reuse_f.flush()
            state.keys_f.flush()
        progress["unique_pubkeys"] = len(state.pubkeys)
        progress["pr_groups"] = len(state.first)
        progress["updated_at"] = utcnow()
        progress["finished_at"] = utcnow()
        atomic_write_json(PROGRESS_PATH, progress)
        finalize.pubkeys = state.pubkeys  # type: ignore
    finally:
        state.close()
    finalize(progress, t0, output)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=210000)
    ap.add_argument("--end", type=int, default=220000)
    ap.add_argument("--output", type=str, default="/results/nonce_reuse.json")
    ap.add_argument("--calibrate-only", action="store_true")
    ap.add_argument("--skip-calibrate", action="store_true")
    args = ap.parse_args()
    ensure_dirs()
    if args.calibrate_only:
        calibrate()
        return
    run_scan(args.start, args.end, Path(args.output))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        append_line(EXCEPTIONS_PATH, f"fatal\n{traceback.format_exc()}")
        traceback.print_exc()
        # Do not die on unexpected errors in the scan loop; main() already continues per-block.
        # A true fatal in setup still exits non-zero so the supervisor can restart.
        sys.exit(1)
