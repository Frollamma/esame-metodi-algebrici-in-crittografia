from hashlib import sha1
import json
from datetime import datetime
from Crypto.Util.number import bytes_to_long, long_to_bytes

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
K = GF(p)
a = K(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC)
b = K(0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1)
E = EllipticCurve(K, (a, b))
G = E(
    0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
    0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
)
E.set_order(0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831 * 0x1)
n = E.order()

R = Zmod(n)


msg = "unlock"
z = bytes_to_long(sha1(msg.encode()).digest())
z = R(z)
r = R(0)

signatures = []
for i in range(1, 60):
    k = R(i)

    s = k ^ (-1) * z
    signatures.append((i, s))

print(signatures)
