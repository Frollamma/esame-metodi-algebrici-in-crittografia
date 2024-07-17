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


# ES 3
import hashlib

# Define the elliptic curve parameters
p = 9739
a = 497
b = 1768

E = EllipticCurve(GF(p), [a, b])
Q_A = E(815,3190)
n_B = 1829

S = n_B * Q_A

# Generate a key by calculating the SHA1 hash of the xx coordinate (take the integer representation of the coordinate and cast it to a string). The flag is the hexdigest you find.
key = hashlib.sha1(str(S[0]).encode()).hexdigest()

print(key)