import threading
import socket
from datetime import datetime
from Crypto.Util import number
from Crypto import Random
import random
# import gensafeprime

#local params
cmd = "#".encode('ascii')

# Now this Host is the IP address of the Server, over which it is running.
# I've user my localhost.
host = "127.0.0.1"
port = 5555 # Choose any random port which is not so common (like 80)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Bind the server to IP Address
server.bind((host, port))
#Start Listening Mode
server.listen()
#List to contain the Clients getting connected and nicknames
clients = []
nicknames = []
secretChatPairs = {} #(userA, userB):(p, g)
dhParams = {} #(p, g):(userA, userB)
# 1.Broadcasting Method
def broadcast(message):
    for client in clients:
        client.send(message)

# 2.Recieving Messages from client then broadcasting
def handle(client):
    while True:
        now = datetime.now()
        current_time = "[" + now.strftime("%H:%M:%S") + "]"
        try:
            msg = message = client.recv(1024)
            msgCheckCommand = msg[0:1].decode('ascii')
            if msgCheckCommand == "#":
                code = int.from_bytes(msg[1:2], 'big')
                if code == 128:
                    userA = nicknames[clients.index(client)]
                    userB = msg[2:].decode('ascii')
                    if userB in nicknames:
                        if ((userA, userB) in secretChatPairs) or ((userB, userA) in secretChatPairs):
                            code = codeToByte(7)
                            client.send(cmd + code + userB.encode('ascii'))
                        else:
                            print(f'{current_time} {userA} needs Diffie-Hellman parameters')
                            code = codeToByte(1)
                            p = 0
                            g = 0
                            while (p and g) or (p, g) in dhParams:
                                p, g = genDhParameter()
                            p = p.to_bytes(256, 'big')
                            g = g.to_bytes(1, 'big')
                            secretChatPairs[(userA, userB)] = (p, g)
                            dhParams[(p, g)] = (userA, userB)
                            client.send(cmd + code + p + g + userB.encode('ascii'))
                    else:
                        code = codeToByte(8)
                        client.send(cmd + code + userB.encode('ascii'))
                elif code == 129:
                    userA = nicknames[clients.index(client)]
                    userB = msg[259:].decode('ascii')
                    p = int.from_bytes(msg[2:258], 'big')
                    g = int.from_bytes(msg[258:259], 'big')
                    dhParams.pop((p, g), None)
                    print(f'{current_time} {userA} needs Diffie-Hellman parameters again')
                    code = codeToByte(1)
                    p = 0
                    g = 0
                    while (p and g) or (p, g) in dhParams:
                        p, g = genDhParameter()
                    p = p.to_bytes(256, 'big')
                    g = g.to_bytes(1, 'big')
                    secretChatPairs[(userA, userB)] = (p, g)
                    dhParams[(p, g)] = (userA, userB)
                    client.send(cmd + code + p + g + userB.encode('ascii'))
                elif code == 130:
                    userA = nicknames[clients.index(client)]
                    userB = msg[258:].decode('ascii')
                    g_a = int.from_bytes(msg[2:258], 'big')
                    print(f'{current_time} {userA} send g_a, sending to {userB}')
                    code = codeToByte(2)
                    clientByUser(userB).send(cmd + code + g_a + userA.encode('ascii'))
                elif code == 131:
                    userB = nicknames[client.index(client)]
                    userA = msg[2:].decode('ascii')
                    print(f'{current_time} {userB} accept Secret Chat with {userA}')
                    code = codeToByte(5)
                    p, g = secretChatPairs[(userA, userB)]
                    p = p.to_bytes(256, 'big')
                    g = g.to_bytes(1, 'big')
                    client.send(cmd + code + p + g + userA.encode('ascii'))
                elif code == 132:
                    userB = nicknames[client.index(client)]
                    userA = msg[2:].decode('ascii')
                    dhParams.pop(secretChatPairs[(userA, userB)], None)
                    secretChatPairs.pop((userA, userB), None)
                    code = codeToByte(4)
                    print(f'{current_time} {userB} decline Secret Chat with {userA}')
                    clientByUser(userA).send(cmd + code + userB.encode('ascii'))
                elif code == 133:
                    g_b = msg[2:258]
                    keyFingerPrint = msg[258:266]
                    userA = msg[266:].decode('ascii')
                    userB = nicknames[client.index(client)]
                    print(f'{current_time} Sending g_b from {userB} to {userA}')
                    code = codeToByte(3)
                    clientByUser(userA).send(cmd + code + g_b + keyFingerPrint + userB.encode('ascii'))
                elif code == 134:
                    userA = nicknames[clients.index(client)]
                    userB = msg[259:].decode('ascii')
                    p = int.from_bytes(msg[2:258], 'big')
                    g = int.from_bytes(msg[258:259], 'big')
                    dhParams.pop((p, g), None)
                    secretChatPairs.pop((userA, userB), None)
                    code = codeToByte(8)
                    print(f'{current_time} {userA} and {userB} failed to create SecretChat Key')
                    clientByUser(userB).send(cmd + code + userA.encode('ascii'))
            else:
                msgDecode = msg.decode('ascii')
                if msgDecode.startswith('KICK'):
                    if nicknames[clients.index(client)] == 'admin':
                        nameToKick = msgDecode[5:]
                        kick_user(nameToKick)
                    else:
                        client.send('Command Refused!'.encode('ascii'))
                elif msgDecode.startswith('BAN'):
                    if nicknames[clients.index(client)] == 'admin':
                        nameToBan = msgDecode[4:]
                        kick_user(nameToBan)
                        with open('bans.txt','a') as f:
                            f.write(f'{nameToBan}\n')
                        print(f'{current_time} {nameToBan} was banned by the Admin!')
                    else:
                        client.send('Command Refused!'.encode('ascii'))  
                else:
                    broadcast(message)   # As soon as message recieved, broadcast it.
        
        except:
            if client in clients:
                index = clients.index(client)
                #Index is used to remove client from list after getting diconnected
                client.remove(client)
                client.close
                nickname = nicknames[index]
                broadcast(f'{nickname} left the Chat!'.encode('ascii'))
                nicknames.remove(nickname)
                break
# Main Recieve method
def recieve():
    while True:
        now = datetime.now()
        current_time ="[" + now.strftime("%H:%M:%S") + "]"
        client, address = server.accept()
        print(f"{current_time} Connected with {str(address)}")
        # Ask the clients for Nicknames
        client.send('NICK'.encode('ascii'))
        nickname = client.recv(1024).decode('ascii')
        # If the Client is an Admin promopt for the password.
        with open('bans.txt', 'r') as f:
            bans = f.readlines()
        
        if nickname+'\n' in bans:
            client.send('BAN'.encode('ascii'))
            client.close()
            continue

        if nickname == 'admin':
            client.send('PASS'.encode('ascii'))
            password = client.recv(1024).decode('ascii')
            # I know it is lame, but my focus is mainly for Chat system and not a Login System
            if password != 'adminpass':
                client.send('REFUSE'.encode('ascii'))
                client.close()
                continue

        nicknames.append(nickname)
        clients.append(client)

        print(f'{current_time} Nickname of the client is {nickname}')
        broadcast(f'{nickname} joined the Chat'.encode('ascii'))
        client.send('Connected to the Server!'.encode('ascii'))

        # Handling Multiple Clients Simultaneously
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

def clientByUser(userName):
    index = nicknames.find(userName)
    return clients[index]

def codeToByte(code):
    return code.to_bytes(1, 'big')

def kick_user(name):
    if name in nicknames:
        name_index = nicknames.index(name)
        client_to_kick = clients[name_index]
        clients.remove(client_to_kick)
        client_to_kick.send('You Were Kicked from Chat !'.encode('ascii'))
        client_to_kick.close()
        nicknames.remove(name)
        broadcast(f'{name} was kicked from the server!'.encode('ascii'))

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

#Calling the main method
print('Server is Listening ...')
recieve()