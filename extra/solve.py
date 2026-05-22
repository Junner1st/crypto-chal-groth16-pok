import hashlib
import json
import sys

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

HOST = "10.13.8.12"
# HOST = "127.0.0.1"
PORT = 1339

context.log_level = "error"

Q = 170141183460469231731687303715884105727
P = 19396094914493492417412352623610788052879
G = 20769187434139310514121985316880384


def log(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr, flush=True)


def short_int(value: int, keep: int = 18) -> str:
    text = str(int(value))
    if len(text) <= keep * 2 + 5:
        return text
    return f"{text[:keep]}...{text[-keep:]} ({len(text)} digits)"


def short_list(values: list[int]) -> str:
    return "[" + ", ".join(short_int(value, keep=10) for value in values) + "]"


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
    log(f"connecting to {HOST}:{PORT}")
    io = remote(HOST, PORT)
    try:
        log("waiting for public parameters")
        banner = io.recvuntil(b"> ").decode(errors="ignore")
        pub = parse_public(banner)
        x_pub = int(pub["X"])
        vk = pub["verifying_key"]
        log(f"parsed issuer public key X = {short_int(x_pub)}")
        log(f"parsed Groth16 verifying key with {len(vk['ic'])} IC points")

        signatures = []
        for idx in range(2):
            message = f"groth16-pok-forged-{idx}"
            log(f"signature {idx + 1}/2: requesting signing session")
            begin = command(io, "begin")
            if not begin.get("ok"):
                raise RuntimeError(f"begin failed: {begin}")

            sid = int(begin["sid"])
            r = int(begin["R"])
            c = hash_challenge(message, r)
            log(f"signature {idx + 1}/2: sid = {sid}")
            log(f"signature {idx + 1}/2: real R = {short_int(r)}")
            log(f"signature {idx + 1}/2: message = {message!r}")
            log(f"signature {idx + 1}/2: c = H(message, R) = {short_int(c)}")

            dummy_r_blind = G
            if dummy_r_blind == r:
                dummy_r_blind = pow(G, 2, P)
            log(f"signature {idx + 1}/2: using dummy R_blind = {short_int(dummy_r_blind)}")

            inputs = public_inputs(r, x_pub, dummy_r_blind, c)
            log(f"signature {idx + 1}/2: Groth16 public inputs = {short_list(inputs)}")
            log(f"signature {idx + 1}/2: forging degenerate Groth16 proof")
            proof = forge_pok(inputs, vk)
            log(
                f"signature {idx + 1}/2: proof pi_a.x = {short_int(proof['pi_a'][0])}, "
                f"pi_a.y = {short_int(proof['pi_a'][1])}"
            )
            issue_payload = {
                "sid": sid,
                "R_blind": dummy_r_blind,
                "c_blind": c,
                "proof": proof,
            }
            log(f"signature {idx + 1}/2: sending issue request")
            issued = command(io, "issue " + json.dumps(issue_payload))
            if not issued.get("ok"):
                raise RuntimeError(f"issue failed: {issued}")
            log(f"signature {idx + 1}/2: received s_blind = {short_int(issued['s_blind'])}")

            signatures.append({"message": message, "R_blind": r, "s": int(issued["s_blind"])})
            log(f"signature {idx + 1}/2: prepared redeemable signature with unissued R")

        log("submitting two forged signatures")
        out = command(io, "submit " + json.dumps(signatures))
        log("service response:")
        print(json.dumps(out, ensure_ascii=False))
    finally:
        io.close()


if __name__ == "__main__":
    main()
