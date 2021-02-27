#!/usr/bin/env python3

import socket
import pyDH
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import socks


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
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

HOST = '127.0.0.1'  
PORT = 65432        


d1 = pyDH.DiffieHellman()
d1_pubkey = d1.gen_public_key()

with socks.socksocket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.set_proxy(socks.SOCKS5, "localhost", 9011)
    s.connect((HOST, PORT))
    s.sendall(d1_pubkey.to_bytes(256, byteorder='big'))
    data = s.recv(256)
    print('Received', repr(data))
    d1_sharedkey = d1.gen_shared_key(int.from_bytes(data, "big") )
    print(d1_sharedkey)

    a = AESCipher(d1_sharedkey)
    z = a.encrypt('hello!')
    s.sendall(z)


