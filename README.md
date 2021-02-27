# Mitm-diffie-hellman
Simulated man in the middle attack on Diffie-Hellman protocol
## How does it work?
1. Alice generate and sends public key to proxy-server
2. Server receives Alice pubkey and generates own public key (open AS key on picture) and sends it to Bob
3. Bob receives key and send his open key to server
4. Server receives Bob pubkey and generates own public key (open BS key on picture) and sends it to Alice
5. Server generates shared key with Alice and shared key with Bob

So server can decript and read all messages that come to it and then encript them and send on.

![not found](scheme_image/shceme.png "description")
