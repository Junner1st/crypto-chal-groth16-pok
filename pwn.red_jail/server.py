#!/usr/bin/env python3
import hashlib
import json
import os
import secrets
import sys

from py_ecc.bn128 import (
    FQ, FQ2,
    G1 as BN254_G1, G2 as BN254_G2, Z1 as BN254_Z1,
    add as bn254_add,
    b as BN254_B, b2 as BN254_B2,
    curve_order as BN254_R, field_modulus as BN254_P,
    is_on_curve as bn254_is_on_curve,
    multiply as bn254_multiply,
    pairing as bn254_pairing,
)

Q = 170141183460469231731687303715884105727
P = 19396094914493492417412352623610788052879
G = 20769187434139310514121985316880384
MAX_LINE = 20_000
MAX_MESSAGE = 256
MAX_JSON_DEPTH = 8
MAX_LIST_LEN = 16
MAX_STR_LEN = 4096
MAX_INT_DIGITS = 100

FLAG = os.environ.get("FLAG", "flag{test}")


def mod_q(x: int) -> int:
    return x % Q


def sample_scalar_nonzero() -> int:
    return secrets.randbelow(Q - 1) + 1


def in_subgroup(y: int) -> bool:
    return 1 <= y < P and pow(y, Q, P) == 1


def hash_challenge(message: str, r_blind: int) -> int:
    msg = message.encode("utf-8")
    rb = r_blind.to_bytes((P.bit_length() + 7) // 8, "big")
    data = b"blind-schnorr/lamb" + len(msg).to_bytes(4, "big") + msg + rb
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % Q


def verify_signature(x_pub: int, message: str, r_blind: int, s: int) -> bool:
    if not isinstance(message, str) or len(message.encode("utf-8")) > MAX_MESSAGE:
        return False
    if not in_subgroup(x_pub) or not in_subgroup(r_blind):
        return False

    c = hash_challenge(message, r_blind)
    lhs = pow(G, mod_q(s), P)
    rhs = (r_blind * pow(x_pub, c, P)) % P
    return lhs == rhs


def _fq(x: int) -> FQ:
    x = int(x)
    if not 0 <= x < BN254_P:
        raise ValueError("FQ coordinate out of range")
    return FQ(x)


def _fq2(xs) -> FQ2:
    if not isinstance(xs, list | tuple) or len(xs) != 2:
        raise ValueError("bad FQ2 coordinate")
    return FQ2([_fq(int(xs[0])).n, _fq(int(xs[1])).n])


def _serialize_g1(point) -> list[int]:
    if point is None:
        return [0, 0]
    return [int(point[0]), int(point[1])]


def _serialize_g2(point) -> list[list[int]]:
    if point is None:
        return [[0, 0], [0, 0]]
    return [
        [int(point[0].coeffs[0]), int(point[0].coeffs[1])],
        [int(point[1].coeffs[0]), int(point[1].coeffs[1])],
    ]


def _parse_g1(raw):
    if raw is None:
        return BN254_Z1
    if not isinstance(raw, list | tuple) or len(raw) != 2:
        raise ValueError("bad G1 point")
    x, y = int(raw[0]), int(raw[1])
    if x == 0 and y == 0:
        return BN254_Z1
    point = (_fq(x), _fq(y))
    if not bn254_is_on_curve(point, BN254_B):
        raise ValueError("G1 point not on curve")
    if bn254_multiply(point, BN254_R) is not None:
        raise ValueError("G1 point not in subgroup")
    return point


def _parse_g2(raw):
    if raw is None:
        return None
    if not isinstance(raw, list | tuple) or len(raw) != 2:
        raise ValueError("bad G2 point")
    if raw == [[0, 0], [0, 0]]:
        return None
    point = (_fq2(raw[0]), _fq2(raw[1]))
    if not bn254_is_on_curve(point, BN254_B2):
        raise ValueError("G2 point not on curve")
    if bn254_multiply(point, BN254_R) is not None:
        raise ValueError("G2 point not in subgroup")
    return point


def _fr_from_hash(label: bytes, *values: int) -> int:
    h = hashlib.sha256(label)
    for value in values:
        h.update(int(value).to_bytes(32, "big", signed=False))
    return int.from_bytes(h.digest(), "big") % BN254_R


def _bounded_json(value, depth: int = 0) -> bool:
    if depth > MAX_JSON_DEPTH:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return len(str(abs(value))) <= MAX_INT_DIGITS
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= MAX_STR_LEN
    if isinstance(value, list):
        return len(value) <= MAX_LIST_LEN and all(_bounded_json(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return len(value) <= MAX_LIST_LEN and all(
            isinstance(key, str)
            and len(key) <= 32
            and _bounded_json(item, depth + 1)
            for key, item in value.items()
        )
    return False


class Groth16Verifier:
    def __init__(self, verifying_key: dict) -> None:
        self.alpha_g1 = _parse_g1(verifying_key["alpha_g1"])
        self.beta_g2 = _parse_g2(verifying_key["beta_g2"])
        self.gamma_g2 = _parse_g2(verifying_key["gamma_g2"])
        self.delta_g2 = _parse_g2(verifying_key["delta_g2"])
        self.ic = [_parse_g1(point) for point in verifying_key["ic"]]

    def verify(self, public_inputs: list[int], proof: dict) -> bool:
        if len(public_inputs) + 1 != len(self.ic):
            return False

        try:
            a = _parse_g1(proof["pi_a"])
            b = _parse_g2(proof["pi_b"])
            c = _parse_g1(proof["pi_c"])
        except Exception:
            return False

        if a is None or b is None or c is None:
            return False

        vk_x = self.ic[0]
        for coeff, value in zip(self.ic[1:], public_inputs, strict=True):
            vk_x = bn254_add(vk_x, bn254_multiply(coeff, int(value) % BN254_R))

        lhs = bn254_pairing(b, a)
        rhs = (
            bn254_pairing(self.beta_g2, self.alpha_g1)
            * bn254_pairing(self.gamma_g2, vk_x)
            * bn254_pairing(self.delta_g2, c)
        )
        return lhs == rhs


POK_IC_SCALARS = [
    _fr_from_hash(b"pok/ic/0"),
    _fr_from_hash(b"pok/ic/R"),
    _fr_from_hash(b"pok/ic/X"),
    _fr_from_hash(b"pok/ic/R_blind"),
    _fr_from_hash(b"pok/ic/c_blind"),
]

POK_VERIFYING_KEY = {
    "alpha_g1": _serialize_g1(BN254_G1),
    "beta_g2": _serialize_g2(BN254_G2),
    "gamma_g2": _serialize_g2(BN254_G2),
    "delta_g2": _serialize_g2(BN254_G2),
    "ic": [_serialize_g1(bn254_multiply(BN254_G1, scalar)) for scalar in POK_IC_SCALARS],
}


def _pok_public_inputs(r: int, x_pub: int, r_blind: int, c_blind: int) -> list[int]:
    return [
        _fr_from_hash(b"pok/R", r),
        _fr_from_hash(b"pok/X", x_pub),
        _fr_from_hash(b"pok/R_blind", r_blind),
        int(c_blind) % BN254_R,
    ]


class PoK:
    def __init__(self, verifier: Groth16Verifier | None = None) -> None:
        self.verifier = verifier or Groth16Verifier(POK_VERIFYING_KEY)

    def verify(self, r: int, x_pub: int, r_blind: int, c_blind: int, proof: dict | None = None) -> bool:
        if proof is None or not isinstance(proof, dict):
            return False
        return self.verifier.verify(_pok_public_inputs(r, x_pub, r_blind, c_blind), proof)


class Issuer:
    def __init__(self, pok=None, issue_budget: int = 2) -> None:
        self.x = sample_scalar_nonzero()
        self.X = pow(G, self.x, P)
        self.pok = pok or PoK()
        self.issue_budget = issue_budget
        self.next_sid = 1
        self.sessions: dict[int, dict] = {}
        self.redeemed_messages: set[str] = set()
        self.issued_r_blinds: set[int] = set()

    def public(self) -> dict:
        return {
            "p": P,
            "q": Q,
            "g": G,
            "X": self.X,
            "issue_budget": self.issue_budget,
            "target": "submit 2 distinct valid signatures after at most 2 issues",
            "pok": "Groth16 BN254 proof over public inputs H(R), H(X), H(R_blind), c_blind",
            "verifying_key": POK_VERIFYING_KEY,
        }

    def begin_issue(self) -> dict:
        sid = self.next_sid
        self.next_sid += 1

        k = sample_scalar_nonzero()
        r = pow(G, k, P)

        self.sessions[sid] = {"k": k, "R": r, "used": False}
        return {"ok": True, "sid": sid, "R": r}

    def issue(self, sid: int, r_blind: int, c_blind: int, proof: dict | None = None) -> dict:
        if self.issue_budget <= 0:
            return {"ok": False, "msg": "issue budget exhausted"}

        session = self.sessions.get(sid)
        if session is None:
            return {"ok": False, "msg": "unknown session"}
        if session["used"]:
            return {"ok": False, "msg": "session already used"}

        r_blind = int(r_blind)
        c_blind = mod_q(int(c_blind))

        if not in_subgroup(r_blind):
            return {"ok": False, "msg": "R_blind not in subgroup"}
        if not self.pok.verify(session["R"], self.X, r_blind, c_blind, proof):
            return {"ok": False, "msg": "invalid proof"}

        s_blind = mod_q(session["k"] + c_blind * self.x)
        session["used"] = True
        self.issue_budget -= 1
        self.issued_r_blinds.add(r_blind)

        return {"ok": True, "s_blind": s_blind}

    def submit(self, signatures: list[dict]) -> dict:
        if len(signatures) != 2:
            return {"ok": False, "msg": "need exactly 2 signatures"}

        seen = set()
        for item in signatures:
            message = item["message"]
            r_blind = int(item["R_blind"])
            s = int(item["s"])

            if not isinstance(message, str) or len(message.encode("utf-8")) > MAX_MESSAGE:
                return {"ok": False, "msg": "bad message"}
            if message in seen:
                return {"ok": False, "msg": "messages must be distinct"}
            if message in self.redeemed_messages:
                return {"ok": False, "msg": "message already redeemed"}
            if r_blind in self.issued_r_blinds:
                return {"ok": False, "msg": "issued signatures cannot be redeemed"}
            if not verify_signature(self.X, message, r_blind, s):
                return {"ok": False, "msg": "invalid signature"}

            seen.add(message)

        self.redeemed_messages |= seen
        return {"ok": True, "flag": FLAG}


def main() -> None:
    issuer = Issuer(PoK(), issue_budget=2)

    print("== Blind Schnorr Coupon Service (Groth16 PoK) ==")
    print(json.dumps(issuer.public()))
    print("Commands:")
    print("  begin")
    print('  issue {"sid": <int>, "R_blind": <int>, "c_blind": <int>, "proof": <groth16 proof>}')
    print('  submit [{"message": <str>, "R_blind": <int>, "s": <int>}, {...}]')
    print("  exit")

    while True:
        sys.stdout.write("> ")
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()

        if len(line.encode("utf-8")) > MAX_LINE:
            print(json.dumps({"ok": False, "msg": "input too large"}))
            continue
        if line == "exit":
            break
        if not line:
            continue

        try:
            if line == "begin":
                print(json.dumps(issuer.begin_issue()))
                continue

            cmd, payload_raw = line.split(" ", 1)
            payload = json.loads(payload_raw)
            if not _bounded_json(payload):
                print(json.dumps({"ok": False, "msg": "input too large"}))
                continue
        except Exception:
            print(json.dumps({"ok": False, "msg": "bad input"}))
            continue

        try:
            if cmd == "issue":
                print(
                    json.dumps(
                        issuer.issue(
                            sid=int(payload["sid"]),
                            r_blind=int(payload["R_blind"]),
                            c_blind=int(payload["c_blind"]),
                            proof=payload.get("proof"),
                        )
                    )
                )
            elif cmd == "submit":
                if not isinstance(payload, list):
                    print(json.dumps({"ok": False, "msg": "submit expects a list"}))
                    continue
                print(json.dumps(issuer.submit(payload)))
            else:
                print(json.dumps({"ok": False, "msg": "unknown command"}))
        except Exception:
            print(json.dumps({"ok": False, "msg": "processing error"}))


if __name__ == "__main__":
    main()
