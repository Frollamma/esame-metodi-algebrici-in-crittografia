# ES 1
# # Define the elliptic curve parameters
# p = 9739
# a = 497
# b = 1768

# # Define the points P, Q, and R
# E = EllipticCurve(GF(p), [a, b])
# P = E(493, 5564)
# Q = E(1539, 4742)
# R = E(4403, 5202)

# # Perform point addition to find S
# S = P + P + Q + R

# # Print the coordinates of S
# print("S =", S.xy())

# # ES 2
# # Define the elliptic curve parameters
# p = 9739
# a = 497
# b = 1768

# # Define the point P
# E = EllipticCurve(GF(p), [a, b])
# P = E(2339,2213)

# # Calculate 7863P
# Q = 7863*P

# # Print the coordinates of Q
# print("Q =", Q.xy())


# # ES 3
# import hashlib

# # Define the elliptic curve parameters
# p = 9739
# a = 497
# b = 1768

# E = EllipticCurve(GF(p), [a, b])
# Q_A = E(815,3190)
# n_B = 1829

# S = n_B * Q_A

# # Generate a key by calculating the SHA1 hash of the xx coordinate (take the integer representation of the coordinate and cast it to a string). The flag is the hexdigest you find.
# key = hashlib.sha1(str(S[0]).encode()).hexdigest()

# print(key)

# # ES 4
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import hashlib


# def is_pkcs7_padded(message):
#     padding = message[-message[-1]:]
#     return all(padding[i] == len(padding) for i in range(0, len(padding)))


# def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
#     # Derive AES key from shared secret
#     sha1 = hashlib.sha1()
#     sha1.update(str(shared_secret).encode('ascii'))
#     key = sha1.digest()[:16]
#     # Decrypt flag
#     ciphertext = bytes.fromhex(ciphertext)
#     iv = bytes.fromhex(iv)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     plaintext = cipher.decrypt(ciphertext)

#     if is_pkcs7_padded(plaintext):
#         return unpad(plaintext, 16).decode('ascii')
#     else:
#         return plaintext.decode('ascii')

# flag_enc = {'iv': 'cd9da9f1c60925922377ea952afc212c', 'encrypted_flag': 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'} # This is the flag encrypted with the shared secret

# # Define the elliptic curve parameters
# p = 9739
# a = 497
# b = 1768

# E = EllipticCurve(GF(p), [a, b])

# x_Q_A = 4726
# n_B = 6534

# y_Q_B_squared = x_Q_A**3 + a*x_Q_A + b
# y_Q_B = pow(y_Q_B_squared, (p + 1)//4, p) # This is true because p = 3 mod 4

# Q_B = E(x_Q_A, y_Q_B)
# S = n_B * Q_B

# print(decrypt_flag(S[0], flag_enc['iv'], flag_enc['encrypted_flag']))

# ES 5
p = 2^255 - 19
a = 486662
b = 1

F = GF(p)
E = EllipticCurve(F, [0, 0, a, b, 0])   # Montgomery form. Actually this curve is very famous and is called Curve25519: https://en.wikipedia.org/wiki/Curve25519

# This assertion is false
# assert p % 4 == 3

x_G = 9
G = E.lift_x(x_G)
print(G.xy())

Q = 0x1337c0decafe * G
print(Q.x())