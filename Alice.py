# sender

import os
import tinyec.ec as ec
import tinyec.registry as reg
import secrets
import hashlib

def textToBin(message):

    message = list(message)
    messageStr = ""

    for i in range(len(message)):
        message[i] = f"{format(ord(message[i]), 'b'):0>8}"
    
    for i in range(len(message)):
        messageStr += message[i]

    return messageStr

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

def listToStr(list):

    str = ""
    for i in range(len(list)):
        str += list[i]

    return str

curve = reg.get_curve('secp256r1')
generator = curve.g
order = curve.field.n
r = secrets.SystemRandom()
alpha = r.randrange(1, order)   

alphaG = alpha * generator

input("\n Press 'Enter' to start the public key exchange")
f = open("message.txt", "w")
f.write(str(alphaG.x) + " " + str(alphaG.y))
f.close()


input("\n Once Bob has also started the public key exchange, press 'Enter'")
f = open("message.txt", "r")
msg_rcv = f.read()
f.close()
os.remove("message.txt")
print("\n The inital key has now been generated")

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

betaG = ec.Point(curve, int(a), int(b))
abg = alpha * betaG

input("\n Press 'Enter' to send a message to Bob")
msg = input("Message: ")
f = open("message.txt", "w")

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

encMsg = xor(textToBin(msg), keyFinal)

print("\n The resulting ciphertext is: " + encMsg)
print("\n The final key is: " + keyFinal)


f.write(encMsg)
f.close()   