import hashlib
import json

from py_ecc.bn128 import (
    FQ,
    FQ2,
    G1 as BN254_G1,
    G2 as BN254_G2,
    add as bn254_add,
    curve_order as BN254_R,
    field_modulus as BN254_P,
    multiply as bn254_multiply,
)
from pwn import context, remote

HOST = "127.0.0.1"
PORT = 1339

context.log_level = "error"

Q = 170141183460469231731687303715884105727
P = 19396094914493492417412352623610788052879
G = 20769187434139310514121985316880384


def mod_q(x: int) -> int:
    return x % Q


def hash_challenge(message: str, r_blind: int) -> int:
    msg = message.encode("utf-8")
    rb = r_blind.to_bytes((P.bit_length() + 7) // 8, "big")
    data = b"blind-schnorr/lamb" + len(msg).to_bytes(4, "big") + msg + rb
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % Q


def fr_from_hash(label: bytes, *values: int) -> int:
    h = hashlib.sha256(label)
    for value in values:
        h.update(int(value).to_bytes(32, "big", signed=False))
    return int.from_bytes(h.digest(), "big") % BN254_R


def fq(x: int) -> FQ:
    x = int(x)
    if not 0 <= x < BN254_P:
        raise ValueError("FQ coordinate out of range")
    return FQ(x)


def fq2(xs) -> FQ2:
    return FQ2([fq(int(xs[0])).n, fq(int(xs[1])).n])


def serialize_g1(point) -> list[int]:
    if point is None:
        return [0, 0]
    return [int(point[0]), int(point[1])]


def serialize_g2(point) -> list[list[int]]:
    if point is None:
        return [[0, 0], [0, 0]]
    return [
        [int(point[0].coeffs[0]), int(point[0].coeffs[1])],
        [int(point[1].coeffs[0]), int(point[1].coeffs[1])],
    ]


def parse_g1(raw):
    if raw == [0, 0]:
        return None
    return (fq(raw[0]), fq(raw[1]))


def forge_pok(public_inputs: list[int], verifying_key: dict) -> dict:
    ic = [parse_g1(point) for point in verifying_key["ic"]]
    vk_x = ic[0]
    for coeff, value in zip(ic[1:], public_inputs, strict=False):
        vk_x = bn254_add(vk_x, bn254_multiply(coeff, int(value) % BN254_R))

    # One non-infinity representative of the cancellation family:
    # e(G2, 2*G1 + vk_x) = e(G2, G1) * e(G2, vk_x) * e(G2, G1)
    # when pi_c = G1 and beta = gamma = delta = G2.
    return {
        "pi_a": serialize_g1(bn254_add(bn254_multiply(BN254_G1, 2), vk_x)),
        "pi_b": serialize_g2(BN254_G2),
        "pi_c": serialize_g1(BN254_G1),
    }


def public_inputs(r: int, x_pub: int, r_blind: int, c_blind: int) -> list[int]:
    return [
        fr_from_hash(b"pok/R", r),
        fr_from_hash(b"pok/X", x_pub),
        fr_from_hash(b"pok/R_blind", r_blind),
        int(c_blind) % BN254_R,
    ]


def parse_public(banner: str) -> dict:
    for line in banner.splitlines():
        line = line.strip()
        if line.startswith("{") and '"verifying_key"' in line:
            return json.loads(line)
    raise RuntimeError("failed to parse public parameters")


def command(io, line: str) -> dict:
    io.sendline(line.encode())
    blob = io.recvuntil(b"> ").decode(errors="ignore")
    for raw in reversed(blob.splitlines()):
        raw = raw.strip()
        if raw.startswith("{"):
            return json.loads(raw)
    raise RuntimeError(f"no json response for command: {line!r}")


def main() -> None:
    io = remote(HOST, PORT)
    try:
        banner = io.recvuntil(b"> ").decode(errors="ignore")
        pub = parse_public(banner)
        x_pub = int(pub["X"])
        vk = pub["verifying_key"]

        signatures = []
        for idx in range(2):
            message = f"groth16-pok-forged-{idx}"
            begin = command(io, "begin")
            if not begin.get("ok"):
                raise RuntimeError(f"begin failed: {begin}")

            sid = int(begin["sid"])
            r = int(begin["R"])
            c = hash_challenge(message, r)

            dummy_r_blind = G
            if dummy_r_blind == r:
                dummy_r_blind = pow(G, 2, P)

            proof = forge_pok(public_inputs(r, x_pub, dummy_r_blind, c), vk)
            issue_payload = {
                "sid": sid,
                "R_blind": dummy_r_blind,
                "c_blind": c,
                "proof": proof,
            }
            issued = command(io, "issue " + json.dumps(issue_payload))
            if not issued.get("ok"):
                raise RuntimeError(f"issue failed: {issued}")

            signatures.append({"message": message, "R_blind": r, "s": int(issued["s_blind"])})

        out = command(io, "submit " + json.dumps(signatures))
        print(json.dumps(out, ensure_ascii=False))
    finally:
        io.close()


if __name__ == "__main__":
    main()
