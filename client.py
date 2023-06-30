# Super, Fucking, Simple.
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import socket
import base64
import time
import rsa
import os
from tkinter import *
from tkinter import ttk


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


class Client:
    def __init__(self):
        self.client_private_key = None
        self.client_public_key = None
        self.server_public_key = None
        self.encryptor = None
        self.password = None
        self.socket = None
        self.host = None
        self.data = ""
        self.name = ""

    # Connect to server
    def connect_server(self, host, password):
        self.host = host
        self.password = hashlib.sha3_224(password.encode()).digest()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('connecting to %s port %s' % (host[0], host[1]))
        self.socket.connect((host[0], host[1]))

    # Set up encryption
    def encryption_setup(self):  # Load public and private key
        if not os.path.exists("server_public_key"):
            exit("You need the server public key to connect.")
        else:
            self.server_public_key = rsa.PublicKey.load_pkcs1(open("server_public_key", "rb").read())
        if os.path.exists("client_public_key") and os.path.exists("client_private_key"):
            self.client_public_key = rsa.PublicKey.load_pkcs1(open("client_public_key", "rb").read())
            self.client_private_key = rsa.PrivateKey.load_pkcs1(open("client_private_key", "rb").read())
        else:
            self.client_public_key, self.client_private_key = rsa.newkeys(2048)
            open("client_public_key", "wb").write(self.client_public_key.save_pkcs1('PEM'))
            open("client_private_key", "wb").write(self.client_private_key.save_pkcs1('PEM'))

    def encrypt_msg(self, msg=None):
        msg = rsa.encrypt(msg, self.server_public_key)
        return msg

    def encrypt_and_send_msg(self, msg=None):
        self.socket.sendall(self.encrypt_msg(msg=self.password) + self.encryptor.encrypt(msg))

    def receive_and_decrypt_msg_response(self):
        return self.encryptor.decrypt(self.socket.recv(16384))


class Game:
    def __init__(self):
        self.server_list = None
        self.server_ips = None
        self.client = None
        self.server_port = None
        self.server_ip = None
        self.menu_frame = None
        self.grid_size = None  # exists to be set later on
        self.tile_labels = {}
        self.tile_icons = {}
        self.tiles = {}
        self.buttons = {}
        self.root = Tk()
        self.main_menu()

    def process_response(self, response):
        command_chain = []
        command = ""
        for letter in response + ',':
            if letter == ',':
                command_chain.append(command)
                command = ""
            else:
                command += letter
        return command_chain

    def send_request(self, message):
        request = str(message)  # May contain 8192 bytes
        print('sending "%s"' % request)
        client.encrypt_and_send_msg(request)  # Message
        response = client.receive_and_decrypt_msg_response()  # Response
        print('received "%s"' % response)
        command_chain = self.process_response(response)
        return command_chain

    def main_menu(self):
        self.server_ips = {"localhost": 34197, "127.0.0.1": 34197}
        self.menu_frame = ttk.LabelFrame(self.root, text="game")
        self.menu_frame.grid()
        join_button = ttk.Button(self.menu_frame, text="join", command=self.join_game)
        join_button.grid()
        selected_server = StringVar()
        selected_server.set(list(self.server_ips.keys())[0])
        self.server_list = ttk.Combobox(self.menu_frame, textvariable=selected_server, state="readonly")
        self.server_list['values'] = list(self.server_ips)
        self.server_list.grid()
        self.root.mainloop()

    def join_game(self):
        self.server_ip = self.server_list.get()
        self.server_port = self.server_ips.get(self.server_list.get())
        client.encryption_setup()
        client.connect_server(host=(self.server_ip, self.server_port), password="joe")
        client.encryptor = AESCipher(str(client.password))
        self.grid_size = int(self.send_request("map_size")[1])  # clears the comma for this specific scenario for the int()
        # client.socket.close()
        self.menu_frame.destroy()
        self.generate_map()

    def poke(self, send_column, send_row):
        message = self.send_request("clicked_on,{},{}".format(send_column, send_row))
        column = int(message[1])
        row = int(message[2])
        self.tiles[row] = ttk.LabelFrame(self.root, text="({}, {})".format(column, row))
        self.tiles[row].grid(row=row, column=column, padx=1, pady=1, sticky="NSEW")
        self.tile_icons[row + column * self.grid_size] = PhotoImage(file="red.png")
        self.tile_labels[row + column * self.grid_size] = ttk.Button(self.tiles[row], image=self.tile_icons[
            row + column * self.grid_size], command=lambda c=column, r=row: self.poke(c, r))
        self.tile_labels[row + column * self.grid_size].grid(row=1, column=0, padx=0, pady=0, sticky="NSEW")

    def generate_map(self):
        for column in range(self.grid_size):
            for row in range(self.grid_size):
                self.tiles[row] = ttk.LabelFrame(self.root, text="({}, {})".format(column, row))
                self.tiles[row].grid(row=row, column=column, padx=1, pady=1, sticky="NSEW")
                self.tile_icons[row+column*self.grid_size] = PhotoImage(file="grass.png")
                self.tile_labels[row+column*self.grid_size] = ttk.Button(self.tiles[row], image=self.tile_icons[row+column*self.grid_size], command=lambda c=column, r=row: self.poke(c, r))
                self.tile_labels[row+column*self.grid_size].grid(row=1, column=0, padx=0, pady=0, sticky="NSEW")
        self.update_map()

    def update_map(self):
        message = ""
        for column in range(self.grid_size):
            for row in range(self.grid_size):
                message += "map_u,{},{},".format(column, row)
        print(self.send_request(message))
        exit()

        def receiver():
            self.root.after(1000, receiver)
        receiver()


if __name__ == '__main__':
    client = Client()
    game = Game()

