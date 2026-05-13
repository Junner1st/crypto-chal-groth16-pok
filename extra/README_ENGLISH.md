# Groth16 PoK

## Challenge Design

The issuer blacklists `R_blind` values used during issuance, so honest blind
signatures cannot be redeemed directly.

The PoK verifier is the intended weak point. It checks a Groth16-looking pairing
equation:

```text
e(pi_b, pi_a) = e(beta, alpha) * e(gamma, vk_x(public_inputs)) * e(delta, pi_c)
```

The verifying key is degenerate:

```text
alpha = G1
beta  = G2
gamma = G2
delta = G2
```

So anyone can make the public-input terms cancel. For example:

```text
pi_a = 2*G1 + vk_x(public_inputs)
pi_b = G2
pi_c = G1
```

This is one representative of a larger cancellation family; the bug is the
degenerate verifying key, not a single proof shape.

## Exploit Process

1. `begin` to get the real session `R = g^k`.
2. Pick a message and compute `c = H(message, R)`.
3. Issue with a dummy subgroup element as `R_blind`, but set `c_blind = c`.
4. Forge the fake Groth16 proof for `(R, X, dummy_R_blind, c_blind)`.
5. Receive `s = k + c*x`.
6. Submit the signature as `(message, R, s)`, which was not blacklisted.
7. Repeat for the second signature.

## FLAG
`CCCTF{0nTheSize0fPalringB4sedNonInteRactiveArguments_1s_da_paPer_of_GRoThl6_and_faaahhhhh__}`