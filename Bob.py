# receiver

import os
import tinyec.ec as ec
import tinyec.registry as reg
import secrets
import hashlib

def textToBin(message):

    message = list(message)

    for i in range(len(message)):
        message[i] = f"{format(ord(message[i]), 'b'):0>8}"
    
    return message

def xor(m, k):

    m = list(m)
    k = list(k)

    c = []
    cStr = ""

    for i in range(len(m)):
        xor = str(int(m[i]) ^ int(k[i]))
        c.append(xor)
    
    for i in range(len(c)):
        cStr += c[i]

    return cStr

def revert(binary):

    n = 8
    chunks = [binary[i:i + n] for i in range(0, len(binary), n)]
    
    o = ""

    for i in range(len(chunks)):
        o += (chr(int(chunks[i], 2)))
    
    return o

def listToStr(list):

    str = ""
    for i in range(len(list)):
        str += list[i]

    return str

curve = reg.get_curve('secp256r1')
generator = curve.g
order = curve.field.n
r = secrets.SystemRandom()
beta = r.randrange(1, order)

betaG = beta * generator

input("\n Press 'Enter' after Alice has started the public key exchange")
f = open("message.txt", "r")
msg_rcv = f.read()
f.close()
os.remove("message.txt")
print("\n The initial key has now been generated: " + msg_rcv)

a = ""
b = ""

for i in range(len(msg_rcv)):
    if msg_rcv[i] == " ":
        break
    else:
        a = a + msg_rcv[i]

for i in range(len(msg_rcv)):
    if i > (len(a)):
        b = b + msg_rcv[i]

alphaG = ec.Point(curve, int(a), int(b))
abg = alphaG * beta

input("\n Press 'Enter' to complete the public key exchange")
f = open("message.txt", "w")
f.write(str(betaG.x) + " " + str(betaG.y))
f.close()

input("\n Press Enter to receive the message from Alice")
f = open("message.txt", "r")
msg_rcv = f.read()
f.close()
os.remove("message.txt")

hash1 = hashlib.sha256()
hash1.update(abg.x.to_bytes(32, "big"))
hash1.update(abg.y.to_bytes(32, "big"))
key1 = format(int(hash1.hexdigest(), 16), 'b')

keyList = list(key1)
keyLen = int(len(keyList) / 2)

r = []
s = []

for i in range(len(keyList)):
    if i < keyLen:
        r.append(keyList[i])
    else:
        s.append(keyList[i])

gammaG = (int(listToStr(r)) * int(listToStr(s))) * generator

hash2 = hashlib.sha256()
hash2.update(gammaG.x.to_bytes(32, "big"))
hash2.update(gammaG.y.to_bytes(32, "big"))
key2 = format(int(hash1.hexdigest(), 16), 'b')

keyFinal = key1 + key2

decMsg = revert(xor(msg_rcv, keyFinal))

print("\n The ciphertext you received is: " + msg_rcv)

print("\n The final key used to decrypt is: " + keyFinal)

print("\n The received message is: " + decMsg)

f.close()