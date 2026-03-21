import os

def gen_link_secret(size: int = 32):
    return os.urandom(size).hex()

def gen_nonce():
    return os.urandom(32)