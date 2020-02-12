#A simple module for Diffie-Hellman key exchanging

#a 2048 bit prime number. Pre-calculated because calculating primes in real time is hard
PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
GENERATOR = 2


def generateKey():
    from binascii import hexlify
    from os import urandom
    return int(hexlify(urandom(32)), base=16)

def getPublicKey(privateKey, generator = GENERATOR, prime = PRIME):
    return pow(generator, privateKey, prime)

def verifyForeignKey(foreignKey, prime = PRIME):
    if 2 <= foreignKey and foreignKey <= (prime - 2):
        if pow(foreignKey, (prime - 1) // 2, prime) == 1:
            return True
    
    return False

def getSharedKey(privateKey, foreignKey, prime = PRIME):
    from hashlib import sha256
    if verifyForeignKey(foreignKey, prime):
        sharedKey = pow(foreignKey, privateKey, prime)
        return sha256(str(sharedKey).encode()).digest()
    else:
        raise ValueError("Invalid foreign key")


def getBitLength(value):
    x = 0
    while (pow(2, x) <= value):
        x += 1
    return x
