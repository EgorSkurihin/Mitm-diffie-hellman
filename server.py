import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import pyDH
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


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



logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        # read and unpack 2 bytes from a client
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        # socks 5
        assert version == SOCKS_VERSION
        assert nmethods > 0

        # get available methods
        methods = self.get_available_methods(nmethods)

        # send welcome message
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

        # if not self.verify_credentials():
        #     return

        # request
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length)
            address = socket.gethostbyname(address)
        port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1,
                                addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):
        is_connected = False # Are Alice and Bob are got their keys?
        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if is_connected:
                    if len(data) == 0:
                        break
                    a1 = AESCipher(alice_sharedkey)
                    decripted_from_alice = a1.decrypt(data)
                    print(f"\nAlice sends: {decripted_from_alice}")

                    a2 = AESCipher(bob_sharedkey)
                    encripted_to_bob = a2.encrypt(decripted_from_alice)
                    data = encripted_to_bob

                else:
                    #get open key from Alice
                    alice_pubkey = int.from_bytes(data, 'big')
                    d1 = pyDH.DiffieHellman()
                    d1_AliceServer_pubkey = d1.gen_public_key() # public key from server to Alice
                    alice_sharedkey = d1.gen_shared_key(alice_pubkey) # shared key between server and Alice
                    print(f'\nShared key between Alice and server is:\n {alice_sharedkey}\n')
                    
                    #send open key to Bob
                    d2 = pyDH.DiffieHellman()
                    d2_BobServer_pubkey = d2.gen_public_key() # public key from server to Bob
                    data = d2_BobServer_pubkey.to_bytes(256, byteorder='big')
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if is_connected:
                    print("\nBob sends: {}".format(data))
                else:
                    bob_pubkey = int.from_bytes(data, 'big')
                    bob_sharedkey = d2.gen_shared_key(bob_pubkey) # shared key between server and Bob
                    print(f'\nShared key between Bob and server is:\n {bob_sharedkey}\n')

                    #send open key to Alice
                    data = d1_AliceServer_pubkey.to_bytes(256, byteorder='big') # send open key to Alice
                    is_connected = True
                if client.send(data) <= 0:
                        break


if __name__ == '__main__':
    with ThreadingTCPServer(('127.0.0.1', 9011), SocksProxy) as server:
        server.serve_forever()
