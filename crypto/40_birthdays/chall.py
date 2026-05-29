import hashlib

def birthday_hash(msg):
	return hashlib.sha256(msg).digest()[12:17]

msg1 = bytes.fromhex(input("Input message 1 in hex: "))
msg2 = bytes.fromhex(input("Input message 2 in hex: "))

if msg1 == msg2:
	print("Those two messages are the same! >:(")

elif birthday_hash(msg1) != birthday_hash(msg2):
	print("Those two messages don't have the same birthday! T.T")

else:
	print("Finally! They have the same birthday ^o^")
	print(open("flag.txt").read())
