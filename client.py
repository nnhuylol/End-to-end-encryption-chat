import socket
import threading
import sympy
import random
import numpy as np
from Crypto.Hash import SHA1, SHA256
from Crypto.Cipher import AES

# Local params
waitingDh = []
cmd = "#".encode('ascii')
secretChatPair = {} #userName: [local_dh, p, g, SecretChatKey, keyFingerPrint, isOriginator]

#List command code

commandList = [
    ("/help", "Show command list"),
    ("/kick [user_name]", "Kick an user"),
    ("/ban [user_name]", "Ban an user"),
    ("/secret_chat [user_name]", "Start end-to-end encryption chat with other with specific user"),
    ("/accept_chat [user_name]", "Accept Secret Chat with specific user"),
    ("/decline_chat [user_name]", "Decline Secret Chat with specific user"),
    ("/sc [user_name]", "Secret Chat with specific user"),
    ("Made by Nguyen Ngoc Huy", "This is my graduation thesis")
]

def getCode(message):
    if message.startswith('/secret_chat'):
        return 128
    if message.startswith('/accept_chat'):
        return 131
    if message.startswith('/decline_chat'):
        return 132
    if message.startswith('/sc'):
        return 135
    return 0

print("Enter /help to show command list")
nickname = input("Choose Your Nickname:")
if nickname == 'admin':
    password = input("Enter Password for Admin:")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Connect to a host
client.connect(('127.0.0.1',5555))

stop_thread = False

def recieve():
    while True:
        global stop_thread
        if stop_thread:
            break    
        # try:
        msg = client.recv(1024)
        msgCheckCommand = msg[0:1].decode('ascii')
        if msgCheckCommand == "#":
            code = int.from_bytes(msg[1:2], 'big')
            if code == 1:
                p = int.from_bytes(msg[2:258], 'big')
                g = int.from_bytes(msg[258:259], 'big')
                userB = msg[259:].decode('ascii')
                # check = checkPG(p, g)
                check = True
                if check:
                    a, g_a = genG(g, p)
                    code = codeToByte(130)
                    g_a = g_a.to_bytes(256, 'big')
                    secretChatPair[userB] = [a, p, g, bytes(), bytes(), False]
                    client.send(cmd + code + g_a + userB.encode('ascii'))
                else:
                    code = codeToByte(129)
                    client.send(cmd + code + msg[2:259] + userB.encode('ascii'))
            elif code == 2:
                g_a = msg[2:258]
                userA = msg[258:].decode('ascii')
                secretChatPair[userA] = [0, 0, 0, g_a, bytes(), True]
                print(f'{userA} want to start Secret Chat!!') 
                print(f'/accept_chat {userA} to accept. /decline_chat {userA} to decline')
            elif code == 3:
                g_b = int.from_bytes(msg[2:258], 'big')
                keyFingerPrint = msg[258:266]
                userB = msg[266:].decode('ascii')
                a, p, g = secretChatPair[userB][0:3]
                key = genKey(g_b, a, p)
                if keyFingerPrint == genKeyFingerPrint(key):
                    secretChatPair[userB] = [a, p, g, key, keyFingerPrint, False]
                    waitingDh.remove(userB)
                    print(f'Key exchange with {userB} is completed! Ready to Secret Chat!')
                    print(f'Use /sc {userB} [content] to text with {userB} in Secret Chat Mode')
                else:
                    print(f'Some wrong while key exchanging with {userB}!Secret Chat interrupted!')
                    waitingDh.remove(userB)
                    secretChatPair.pop(userB, None)
                    p = p.to_bytes(256, 'big')
                    g = g.to_bytes(1, 'big')
                    code = codeToByte(134)
                    client.send(cmd + code + p + g + userB.encode('ascii'))
            elif code == 4:
                userB = msg[2:].decode('ascii')
                print(f'{userB} decline Secret Chat with you')
                waitingDh.remove(userB)
            elif code == 5:
                p = int.from_bytes(msg[2:258], 'big')
                g = int.from_bytes(msg[258:259], 'big')
                userA = msg[259:].decode('ascii')
                g_a = int.from_bytes(secretChatPair[userA][3], 'big')
                b, g_b = genG(g, p)
                key = genKey(g_a, b, p)
                keyFingerPrint = genKeyFingerPrint(key)
                secretChatPair[userA] = [b, p, g, key, keyFingerPrint, True]
                code = codeToByte(133)
                g_b = g_b.to_bytes(256, 'big')
                client.send(cmd + code + g_b + keyFingerPrint + userA.encode('ascii'))
            elif code == 6:
                userB = msg[2:].decode('ascii')
                waitingDh.remove(userB)
                print(f'Already in Secret Chat with {userB}')
            elif code == 7:
                userB = msg[2:].decode('ascii')
                waitingDh.remove(userB)
                print(f'{userB} is not online yet')
            elif code == 8:
                userA = msg[2:].decode('ascii')
                print(f'Something wrong while key exchanging with {userA}! Secret Chat interrupted!')
                secretChatPair.pop(userA, None)
            # elif code == 9:
            #     userA = msg[2:].decode('ascii')
            #     print('Invite yourself! Really?')
            #     waitingDh.remove(userA)
            elif code == 10:
                nameLengthSender = int.from_bytes(msg[2:3], 'big')
                sender = msg[3:3+nameLengthSender].decode('ascii')
                keyFingerPrint = msg[3+nameLengthSender:11+nameLengthSender]
                msg_key = msg[11+nameLengthSender:27+nameLengthSender]
                key, keyFingerPrintLocal, isOriginator = secretChatPair[sender][3:]
                if keyFingerPrint == keyFingerPrintLocal:
                    encryptedData = msg[27+nameLengthSender:]
                    aes_key, aes_iv = kdf(key, msg_key, isOriginator)
                    M = aes_ige_dec(aes_key, aes_iv, encryptedData)
                    msg_key_local = genMsgKey(key, M, isOriginator)
                    if msg_key_local == msg_key:
                        length = M[0:4]
                        length_num = int.from_bytes(length, 'big')
                        text = M[40:(length_num+4)].decode('ascii')
                        print(f'[SC]{sender}: {text}')
                    else:
                        print(f'Something wrong while Secret Chat with {sender}! Be careful!')
                else:
                    print(f'Something wrong while Secret Chat with {sender}! Be careful!')
        else:
            messageDecode = msg.decode('ascii')
            if messageDecode == 'NICK':
                client.send(nickname.encode('ascii'))
                next_message = client.recv(1024).decode('ascii')
                if next_message == 'PASS':
                    client.send(password.encode('ascii'))
                    if client.recv(1024).decode('ascii') == 'REFUSE':
                        print("Connection is Refused !! Wrong Password")
                        stop_thread = True
                # Clients those are banned can't reconnect
                elif next_message == 'BAN':
                    print('Connection Refused due to Ban')
                    client.close()
                    stop_thread = True
            else:
                print(messageDecode)
        # except:
        #     print('Error Occured while Connecting')
        #     client.close()
        #     break
        
def write():
    while True:
        if stop_thread:
            break
        #Getting Messages
        message = f'{nickname}: {input("")}'
        
        realMessage = message[len(nickname)+2:]
        
        if realMessage.startswith('/'):
            if nickname == 'admin':
                if realMessage.startswith('/kick'):
                    # 2 for : and whitespace and 6 for /KICK
                    client.send(f'KICK {realMessage[6:]}'.encode('ascii'))
                elif realMessage.startswith('/ban'):
                    # 2 for : and whitespace and 5 for /BAN
                    client.send(f'BAN {realMessage[5:]}'.encode('ascii'))
            if realMessage.startswith('/help'):
                print ("=============== COMMAND LIST ====================")
                print ("{:<30} {:<100}".format('Command', 'Description'))
                for command, description in commandList:
                    print ("{:<30} {:<100}".format(command, description))
                print ("=================================================")
            else:
                code = getCode(realMessage)
                if code != 0:
                    content = realMessage[realMessage.find(" ") + 1 :]
                    if code == 128:
                        if content in waitingDh:
                            print(f'Already send Secret Chat invite to {content}')
                        elif content == nickname:
                            print('Invite yourself! Really?')
                        else:
                            waitingDh.append(content)
                            print(f'Key exchange with {content} is in progress...')
                            client.send(cmd + codeToByte(code) + f'{content}'.encode('ascii'))
                    elif code == 135:
                        userName = content[:content.find(" ")]
                        if userName in secretChatPair:
                            key, keyFingerPrint, isOriginator = secretChatPair[userName][3:]
                            text = content[content.find(" ") + 1 :]
                            payload = packData(text)
                            msg_key = genMsgKey(key, payload, not isOriginator)
                            aes_key, aes_iv = kdf(key, msg_key, not isOriginator)
                            C = aes_ige_enc(aes_key, aes_iv, payload)
                            nameLength = len(userName).to_bytes(1, 'big')
                            client.send(cmd + codeToByte(code) + nameLength + userName.encode('ascii') + keyFingerPrint + msg_key + C)
                        else:
                            print(f'You are not in Secret Chat with {userName}!') 
                            print(f'You can start Secret Chat with /secret_chat {userName}')
                    else:
                        client.send(cmd + codeToByte(code) + f'{content}'.encode('ascii'))
                else:
                    print("Wrong Command! Enter /help to show command list")
        else:
            client.send(message.encode('ascii'))

def codeToByte(code):
    return code.to_bytes(1, 'big')

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

recieve_thread = threading.Thread(target=recieve)
recieve_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()