# Groth16 PoK

## 題目設計

簽發端會把簽發過程中使用過的 `R_blind` 加入黑名單，因此正常流程取得的盲簽章無法直接拿去兌換。

去期弱點是 PoK verifier，它會檢查一個看起來像 Groth16 的 pairing function

```text
e(pi_b, pi_a) = e(beta, alpha) * e(gamma, vk_x(public_inputs)) * e(delta, pi_c)
```

verifier key 是退化的

```text
alpha = G1
beta  = G2
gamma = G2
delta = G2
```

任何人都可以讓 public input 對應的項互相抵消

```text
pi_a = 2*G1 + vk_x(public_inputs)
pi_b = G2
pi_c = G1
```

這只是更大一族抵消形式中的其中一個代表。真正的漏洞是退化的驗證金鑰，而不是某個特定 proof 形狀。

## 解法流程

1. 使用 `begin` 取得真正 session 的 `R = g^k`
2. 選一個 message，並計算 `c = H(message, R)`
3. 簽發時使用一個假的 subgroup element 作為 `R_blind`，但設定 `c_blind = c`
4. 針對 `(R, X, dummy_R_blind, c_blind)` 偽造假的 Groth16 proof
5. 收到 `s = k + c*x`
6. 送出未被黑名單擋下的簽章 `(message, R, s)`
7. 對第二個簽章重複 1-6

## FLAG
`CCCTF{0nTheSize0fPalringB4sedNonInteRactiveArguments_1s_da_paPer_of_GRoThl6_and_faaahhhhh__}`