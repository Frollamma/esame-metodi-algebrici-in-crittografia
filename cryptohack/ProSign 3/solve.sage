# Let p be a prime and let E be an elliptic curve on a filed K=GF(p), let G be the generator point, let q be the order of G. If Alice is a person who wants to sign a message and Bob wants to check if a message was signed by Alice, ECDSA works as follows:
# Key generation:
# 1. Alice chooses a random integer d in the range [1, q-1], the integer d is the private key of Alice
# 2. Alice computes the point A = dG, the point A is the public key of Alice
# Signature:
# 1. Alice wants to sign a message m
# 2. Alice chooses a random integer k in the range [1, q-1]
# 3. Alice computes the point kG = (x, y) and the integer r = x mod q
# 4. Alice computes the integer z = H(m) where H is a hash function
# 5. Alice computes the integer s = k^(-1)(z + d*r) mod q
# 6. Alice sends the pair (r, s) to Bob
# Verification:
# 1. Bob wants to verify the signature (r, s) of the message m
# 2. Bob computes the integer z = H(m)
# 3. Bob computes the integer u = z s^(-1) mod q and the integer v = r s^(-1) mod q
# 4. Bob computes the point uG + vA = (x, y)
# 5. If the point is the point at infinity, the signature is invalid. Otherwise, the signature is valid if r = x mod q
#
# In this challenge we have a way to guess k and we can get the signature (r1, s1) of a known message m1, we will recover the private key d of Alice.
# We will use the following formula to recover the private key d:
# d = (k s1 - z1) r1^(-1) mod q
# This formula is derived from the formula s = k^(-1)(z + d*r) mod q and it holds for the signature (r1, s1) of the message m1. Now that we recovered the private key d, we can sign whatever message m2, that in our case will be "unlock", and get a signature (r2, s2) as we were Alice.


from hashlib import sha1
import json
from datetime import datetime
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Pwn4Sage.pwn import remote, context

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
q = G.order()
R = Zmod(q)

context.log_level = "error"
r = remote("socket.cryptohack.org", 13381)

packet = {"option": "sign_time"}

response = r.recvline()
r.sendline(json.dumps(packet).encode())
response = r.recvline()
response = json.loads(response)
print(response)

msg = response["msg"]
r1 = R(int(response["r"], 16))
s1 = R(int(response["s"], 16))

hsh = sha1(msg.encode()).digest()
z1 = R(bytes_to_long(hsh))

# Sign the message "unlock"
msg = "unlock"
hsh = sha1(msg.encode()).digest()
z2 = R(bytes_to_long(hsh))

for k in range(1, 60):
    d = (k * s1 - z1) * r1 ^ (-1)

    r2 = R((k * G).xy()[0])
    s2 = (z2 + d * r2) * R(k) ^ (-1)

    print(r2, s2)
    packet = {"option": "verify", "msg": "unlock", "r": hex(int(r2)), "s": hex(int(s2))}
    r.sendline(json.dumps(packet).encode())
    response = r.recvline()
    response = json.loads(response)
    print(response)
