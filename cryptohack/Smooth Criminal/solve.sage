from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import os

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

p = 310717010502520989590157367261876774703
a = 2
b = 3

E = EllipticCurve(GF(p), [a, b])
print(f"Factorization of the order of the elliptic curve: {factor(E.order())}")
# Factorization of the order of the elliptic curve: 2^2 * 3^7 * 139 * 165229 * 31850531 * 270778799 * 179317983307
# The order of E can be factored into a product of powers of small primes and we know that this curve is vulnerable to Pohlig-Hellman attack

G_x = 179210853392303317793440285562762725654
G_y = 105268671499942631758568591033409611165
G = E(G_x, G_y)

B_x = 272640099140026426377756188075937988094
B_y = 51062462309521034358726608268084433317
B = E(B_x, B_y)

Q_A = E(280810182131414898730378982766101210916, 291506490768054478159835604632710368904)

# Calculate discrete logarithm of Q_A to the base G
n_A = Q_A.log(G)

S = n_A * B
shared_secret = S[0]

flag_enc = {'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}

flag = decrypt_flag(shared_secret, flag_enc['iv'], flag_enc['encrypted_flag'])
print(flag)