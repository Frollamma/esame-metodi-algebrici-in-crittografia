from pwn import remote
import json

# Connect to the server
r = remote("socket.cryptohack.org", 13382)

G = [
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
]

d = 2
R = [
    15520159875205514130255899098025123715054849599936616868365830290232639266390,
    35332573964480432986660122673305225849700662492297568815244635356931754804527,
]  # Taken from cryptohack/Curveball/solve.sage

packet = {
    "private_key": d,  # Example private key, adjust as needed
    "host": "www.bing.com",  # Example host, adjust as needed
    "curve": "secp256r1",
    "generator": R,
}

# Send the packet as JSON
packet = json.dumps(packet)

print(packet)

r.sendline(packet)

r.interactive()

# # Receive the response
# response = r.recvline().decode().strip()
# print("Response from server:", response)

# Close the connection
r.close()

