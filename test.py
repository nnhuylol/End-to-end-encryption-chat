import numpy as np
import sympy
from Crypto.Util import number
from Crypto import Random
import random
from Crypto.Hash import SHA1, SHA256
from Crypto.Cipher import AES
# import gensafeprime

def packData(text):
    payload = bytes()
    zeroInt = 0
    payloadType = zeroInt.to_bytes(4, 'big')
    randomBytes = np.random.bytes(16)
    layer = payloadType
    inSeqNo = payloadType
    outSeqNo = payloadType
    messageType = payloadType
    messageObject = text.encode('ascii')
    #create payload without length value
    payload += payloadType
    payload += randomBytes
    payload += layer
    payload += inSeqNo
    payload += outSeqNo
    payload += messageType
    payload += messageObject
    #create payload without padding
    length = len(payload).to_bytes(4, 'big')
    payload = length + payload
    padding = np.random.bytes(12 + 16 - (12 + len(payload)) % 16)
    payload += padding
    #test payload information
    # a = "helloworld!"
    # payload1 = packData(a)
    # length = payload1[0:4]
    # length_num = int.from_bytes(length, 'big')
    # print(length_num)
    # text = payload1[40:(length_num+4)]
    # print(text.decode('utf-8'))
    return payload
def genDhParameter():
    while True:
        p = number.getPrime(2048, Random.new().read)
        # p = gensafeprime.generate(2048)
        if random.randrange(2,7) == 4:
            return p, 4
        if p % 8 == 7:
            return p, 2
        if p % 3 == 2:
            return p, 3
        if p % 5 == 1 or p % 5 == 4:
            return p, 5
        if p % 24 == 19 or p % 24 == 23:
            return p, 6
        if p % 7 == 3 or p % 7 == 5 or p % 7 == 6:
            return p, 7
    
def checkPG(p, g):
    switcher = {
        2: p % 8 == 7,
        3: p % 3 == 2,
        4: True,
        5: p % 5 == 1 or p % 5 == 4,
        6: p % 24 == 19 or p % 24 == 23,
        7: p % 7 == 3 or p % 7 == 5 or p % 7 == 6
    }
    return switcher.get(g, False) and sympy.isprime(p) and sympy.isprime((p-1)//2)
def genG(g, p):
    while True:
        a = random.getrandbits(2048)
        res = pow(g, a, p)
        if 2**(2048-64) <= res and res <= p-2**(2048-64): 
            return a, pow(g, a, p)
def genKey(g, a, p):
    res = pow(g, a, p)
    res = res.to_bytes(256, 'big')
    return res
def genKeyFingerPrint(key):
    return SHA1.new(key).digest()[11:19]
def genMsgKey(key, payload, isOriginator = False):
    x = 8
    if isOriginator:
        x = 0
    msg_key_large = SHA256.new(key[88+x:120+x]+payload).digest()
    return msg_key_large[8:24]
def kdf(key, msg_key, isOriginator = False):
    x = 8
    if isOriginator:
        x = 0
    a = SHA256.new(msg_key + key[x : x+36]).digest()
    b = SHA256.new(key[40+x:76+x]).digest()
    aes_key = a[0:8]+b[8:24]+a[24:32]
    aes_iv = b[0:8]+a[8:24]+b[24:32]
    return aes_key, aes_iv
def XOR(one, two):
    return bytes(a^b for (a,b) in zip(one, two))
def aes_ige_enc(key, iv, M):
    aes = AES.new(key, AES.MODE_ECB)
    c_prev = iv[0:16]
    m_prev = iv[16:32]
    C = bytes()
    for i in range(0, len(M), 16):
        m = M[i:i+16]
        aes_enc_in = XOR(m, c_prev)
        aes_enc_out = aes.encrypt(aes_enc_in)
        c = XOR(aes_enc_out, m_prev)
        m_prev = m
        c_prev = c
        C += c
    return C
def aes_ige_dec(key, iv, C):
    aes = AES.new(key, AES.MODE_ECB)
    c_prev = iv[0:16]
    m_prev = iv[16:32]
    M = bytes()
    for i in range(0, len(C), 16):
        c = C[i:i+16]
        aes_enc_in = XOR(c, m_prev)
        aes_enc_out = aes.decrypt(aes_enc_in)
        m = XOR(aes_enc_out, c_prev)
        m_prev = m
        c_prev = c
        M += m
    return M
p, g = genDhParameter()
a, g_a = genG(g,p)
b, g_b = genG(g,p)
key = genKey(g_a, b, p)
payload = packData("This is encrypted!")
length = payload[0:4]
length_num = int.from_bytes(length, 'big')
print(length_num)
text1 = payload[40:(length_num+4)]
print(text1.decode('ascii'))
msg_key = genMsgKey(key, payload, True)
aes_key, aes_iv = kdf(key, msg_key, True)
C = aes_ige_enc(aes_key, aes_iv, payload)
M = aes_ige_dec(aes_key, aes_iv, C)
length = M[0:4]
length_num = int.from_bytes(length, 'big')
text2 = M[40:(length_num+4)]
print(text2.decode('ascii'))
print("DIFFIE-HELLMAN PARAMETERS==============")
print("P =")
print(p)
print("G =")
print(g)
print("A =")
print(a)
print("B =")
print(b)
print("G_A =")
print(g_a)
print("G_B =")
print(g_b)
print("PAYLOAD=========================")
print(payload)
print("KEY=============")
print(key)
print("KEY_FINGERPRINT==========")
print(genKeyFingerPrint(key))
print("ENCRYPTION===========")
print(C)
# print(checkPG(p, g))