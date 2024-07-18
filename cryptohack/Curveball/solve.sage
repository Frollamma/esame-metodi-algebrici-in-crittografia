# Taken from https://neuromancer.sk/std/secg/secp256r1
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
K = GF(p)
a = K(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC)
b = K(0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)
E = EllipticCurve(K, (a, b))
G = E(
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
E.set_order(0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 * 0x1)

P = E(
    0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531,
    0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A,
)
d = 2

# Find inverse of d modulo order of E
d_inv = inverse_mod(d, E.order())

R = d_inv * P

print(R.xy())

# Result: (15520159875205514130255899098025123715054849599936616868365830290232639266390, 35332573964480432986660122673305225849700662492297568815244635356931754804527)
