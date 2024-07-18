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

for i in range(1, 60):
    k = i
    d = (k * s1 - z1) * r1 ^ (-1)

    r2 = R((k * G).xy()[0])
    s2 = (z2 + d * r2) * R(k) ^ (-1)

    print(r2, s2)
    packet = {"option": "verify", "msg": "unlock", "r": hex(int(r2)), "s": hex(int(s2))}
    r.sendline(json.dumps(packet).encode())
    response = r.recvline()
    response = json.loads(response)
    print(response)
