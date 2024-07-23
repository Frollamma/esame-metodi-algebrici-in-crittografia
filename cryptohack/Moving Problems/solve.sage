import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def analyze_curve(E, G, Q_A, Q_B):
    E_order = E.order()
    
    print(f"Curve order: {E_order}")
    print(f"Curve order nbits: {E_order.nbits()}")
    
    E_order_factorization = factor(E_order)
    E_order_biggest_factor = E_order_factorization[-1][0]
    print(f"Curve order factorization: {E_order_factorization}")
    print(f"Curve order biggest factor: {E_order_biggest_factor}")
    print(f"Curve order biggest factor nbits: {E_order_biggest_factor.nbits()}")
    
    print(f"Generator: {G.xy()}")
    print(f"Generator order: {G.order()}")
    print(f"Generator order nbits: {G.order().nbits()}")

    print(f"Q_A: {Q_A.xy()}")
    print(f"Q_A order: {Q_A.order()}")
    print(f"Q_A order nbits: {Q_A.order().nbits()}")

    print(f"Q_B: {Q_B.xy()}")
    print(f"Q_B order: {Q_B.order()}")
    print(f"Q_B order nbits: {Q_B.order().nbits()}")


def decrypt_flag(shared_secret: int, data: dict):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode("ascii"))
    key = sha1.digest()[:16]
    # Decrypt flag
    iv = bytes.fromhex(data["iv"])
    ciphertext = bytes.fromhex(data["encrypted_flag"])

    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(ciphertext), 16)

    return flag


# Define Curve params
p = 1331169830894825846283645180581
a = -35
b = 98
E = EllipticCurve(GF(p), [a, b])
G = E(479691812266187139164535778017, 568535594075310466177352868412)

Q_A = E(1110072782478160369250829345256, 800079550745409318906383650948)
Q_B = E(1290982289093010194550717223760, 762857612860564354370535420319)
ciphertext_data = {
    "iv": "eac58c26203c04f68d63dc2c58d79aca",
    "encrypted_flag": "bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d",
}

analyze_curve(E, G, Q_A, Q_B)
# Curve order: 1331169830894823538756977170156
# Curve order nbits: 101
# Curve order factorization: 2^2 * 7 * 271^2 * 23687^2 * 1153763334005213
# Curve order biggest factor: 1153763334005213
# Curve order biggest factor nbits: 51
# Generator: (479691812266187139164535778017, 568535594075310466177352868412)
# Generator order: 103686954799254136375814
# Generator order nbits: 77
# Q_A: (1110072782478160369250829345256, 800079550745409318906383650948)
# Q_A order: 103686954799254136375814
# Q_A order nbits: 77
# Q_B: (1290982289093010194550717223760, 762857612860564354370535420319)
# Q_B order: 51843477399627068187907
# Q_B order nbits: 76

# Smooth Criminal results
# Curve order: 310717010502520989590206149059164677804
# Curve order nbits: 128
# Curve order factorization: 2^2 * 3^7 * 139 * 165229 * 31850531 * 270778799 * 179317983307
# Curve order biggest factor: 179317983307
# Curve order biggest factor nbits: 38
# Generator: (179210853392303317793440285562762725654, 105268671499942631758568591033409611165)
# Generator order: 155358505251260494795103074529582338902
# Generator order nbits: 127
# Q_A: (280810182131414898730378982766101210916, 291506490768054478159835604632710368904)
# Q_A order: 77679252625630247397551537264791169451
# Q_A order nbits: 126
# Q_B: (272640099140026426377756188075937988094, 51062462309521034358726608268084433317)
# Q_B order: 155358505251260494795103074529582338902
# Q_B order nbits: 127

u = 
# n_A = G.discrete_log(Q_A)

shared_secret = n_A * Q_B
flag = decrypt_flag(shared_secret, ciphertext_data)
print(flag)
