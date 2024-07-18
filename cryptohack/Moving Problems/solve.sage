import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode("ascii"))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data["iv"] = iv.hex()
    data["encrypted_flag"] = ciphertext.hex()
    return data


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

n_A = G.discrete_log(Q_A)

shared_secret = n_A * Q_B
flag = decrypt_flag(shared_secret, ciphertext_data)
print(flag)
