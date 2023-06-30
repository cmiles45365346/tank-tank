# Super, Fucking, Simple.
from Crypto.Cipher import AES
from Crypto import Random
import threading
import hashlib
import random
import socket
import base64
import time
import rsa
import os


# Stuff you do not read
# https://stackoverflow.com/questions/12524994/encrypt-and-decrypt-using-pycrypto-aes-256#comment80992309_21928790
class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s.encode()) % self.bs) * chr(self.bs - len(s.encode()) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class Server:
    def __init__(self):
        self.server_private_key = None
        self.server_public_key = None
        self.names = []
        self.keys = []

    # Set up encryption
    def encryption_setup(self):  # Load public and private key
        if os.path.exists("server_public_key") and os.path.exists("server_private_key"):
            self.server_public_key = rsa.PublicKey.load_pkcs1(open("server_public_key", "rb").read())
            self.server_private_key = rsa.PrivateKey.load_pkcs1(open("server_private_key", "rb").read())
        else:
            self.server_public_key, self.server_private_key = rsa.newkeys(2048)
            open("server_public_key", "wb").write(self.server_public_key.save_pkcs1('PEM'))
            open("server_private_key", "wb").write(self.server_private_key.save_pkcs1('PEM'))

    def decrypt_msg(self, msg=None):
        try:
            msg = rsa.decrypt(msg, self.server_private_key)
            return msg
        except Exception as e:
            print("Failure occurred: {}".format(e))


# Stuff you read
class Game:
    def __init__(self):
        self.passwords = []
        self.usernames = {}
        self.points = {}
        self.health = {}
        self.tiles = {}
        self.daily_points = 1
        self.grid_size = 5  # map size x and y
        self.make_map()

    def make_map(self):
        for column in range(self.grid_size):
            for row in range(self.grid_size):
                self.tiles[row + column * self.grid_size] = "grass"

    def process_request(self, msg, password):
        msg = msg.lower()
        command_chain = []
        command = ""
        response = ""
        for letter in msg + ',':
            if letter == ',':
                command_chain.append(command)
                command = ""
            else:
                command += letter
        for item in range(len(command_chain)):
            if command_chain[item] == "register":
                if not self.passwords.__contains__(password):
                    self.passwords.append(password)
                    self.points[password] = 0
                    self.health[password] = 3
                    response += "acknowledged" + ','
                response += "acknowledged" + ','
            if command_chain[item] == "hello":
                response += "Hi lmao" + ','
            if command_chain[item] == "clicked_on":
                response += "clicked_on,{},{}".format(command_chain[item+1], command_chain[item+2]) + ','
            if command_chain[item] == "map":
                response += "map," + str(command_chain[item+1]) + "," + str(command_chain[item+2]) + "," + self.tiles[
                    command_chain[item+1] + command_chain[item+2] * self.grid_size] + ','
            if command_chain[item] == "mapSize":
                response += str(self.grid_size) + ','
            if command_chain[item] == "points":
                pass
        return response  # What client sees


class ServerThread(threading.Thread):
    def __init__(self, ip, port):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.password = None  # User password
        self.encryptor = None  # Encryption object
        self.response = None  # response from server to user
        self.msg = None
        self.timeout = 10  # seconds of not receiving any messages to time out after
        self.counter = 0
        print("[+] New thread started for " + self.ip + ":" + str(self.port))

    def run(self):
        print("Connection from : " + self.ip + ":" + str(self.port))
        while True:
            try:
                # Receive and expire if dead
                self.msg = serversock.recv(16384)
                if self.msg == b'':
                    self.counter += 0.2
                    time.sleep(0.2)
                    if self.counter >= self.timeout:
                        break
                    continue

                self.password = server.decrypt_msg(self.msg[0:256])
                self.encryptor = AESCipher(str(self.password))
                self.msg = self.encryptor.decrypt(self.msg[256:])

                print('received "%s"' % self.msg)
                print("Processing request")
                # Do shit here
                self.response = game.process_request(self.msg, self.password)

                # Response
                print('sending data back to the client')
                serversock.sendall(self.encryptor.encrypt(self.response))  # Pass str into encryptor
                self.counter = 0
            except Exception as e:
                print("Failure occurred: {}".format(e))
        print("[-] Client disconnected...")
        print("[-] Thread stopped for " + self.ip + ":" + str(self.port))


if __name__ == '__main__':
    server = Server()
    server.encryption_setup()
    game = Game()

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    tcpsock.bind(('192.168.1.15', 34197))
    threads = []
    while True:
        tcpsock.listen(4)
        print("\nListening for incoming connections...")
        (serversock, (ip, port)) = tcpsock.accept()
        newthread = ServerThread(ip, port)
        newthread.start()
        threads.append(newthread)

    for t in threads:
        t.join()
