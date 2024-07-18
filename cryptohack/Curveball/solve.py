from pwn import remote
import json
from fastecdsa.point import Point as BasePoint

class Point(BasePoint):
    def __abs__(self):
        """
        Returns a fake value of 100
        """
        return 100

class MyInt(int):
    def __abs__(self):
        return 100

# Connect to the server
r = remote('socket.cryptohack.org', 13382)

G = [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5]

# Craft the packet. This is an example; adjust based on your goal.
my_num = MyInt(1)
packet1 = {
    "private_key": 4,  # Example private key, adjust as needed
    "host": "www.bing.com",  # Example host, adjust as needed
    "curve": "secp256r1",
    "generator": G
}
packet2 = {
    "private_key": 2,  # Example private key, adjust as needed
    "host": "www.bing.com",  # Example host, adjust as needed
    "curve": "secp256r1",
    "generator": G
}

# Send the packet as JSON
packet1 = json.dumps(packet1)
packet2 = json.dumps(packet2)

print(packet1)
print(packet2)

r.sendline(packet1)

r.close()

r = remote('socket.cryptohack.org', 13382)
r.sendline(packet2)
# r.interactive()

# # Receive the response
# response = r.recvline().decode().strip()
# print("Response from server:", response)

# Close the connection
r.close()



# Devi trovare un P ed m qualsiasi tali che Q = mP con m != 1
# Cosa puoi fare? Puoi calcolare P = m^(-1)Q, dove m^(-1) è l'inverso moltiplicativo di m modulo l'ordine della curva (che è un parametro pubblico o alla  peggio lo trovi con sage credo).