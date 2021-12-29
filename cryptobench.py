'''
Created on Dec 29, 2021

@author: boogie
'''
'''
Created on Dec 22, 2021

@author: boogie
'''
import os
import time
import traceback
import pprofile
import cffi
import aeadpy


from libnacl.aead import AEAD
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.backends.openssl import aead as opensslaead
from multiprocessing import Process, Pipe, cpu_count

k1 = 2 ** 17
sizes = [2 ** 4, 2 ** 8, 2 ** 12, 2 ** 16, k1, int(k1 * 1.5), k1 * 2, k1 * 3, k1 * 4, k1 * 5, k1 * 6, k1 * 7, k1 * 8]
profiler = pprofile.Profile()

_ENCRYPT = 1
_DECRYPT = 0

def worker(i, conn, callback):
    count = acttime = 0
    startt = time.time()
    args = conn.recv()
    while acttime < 3:
        callback(*args)
        count += 1
        acttime = time.time() - startt
    conn.send((acttime, count))


class manager:
    def __init__(self, callback, timeout):
        self.timeout = timeout
        self.pipes = []
        self.wcount = cpu_count()
        self.cb = callback
        self.p = []
        for i in range(self.wcount):
            parent_conn, child_conn = Pipe()
            self.pipes.append(parent_conn)
            p = Process(target=worker, args=[i, child_conn, callback], name=str(i))
            self.p.append(p)
            p.start()

    def encrypt(self, *args):
        for p in self.pipes:
            p.send(args)
                
    def close(self):
        for p in self.p:
            p.join()
        acttime = count = 0
        for p in self.pipes:
            t, c = p.recv()
            if t > acttime:
                acttime = t
            count += c
        return acttime, count
            


def _bench(callback, content, key, nonce):
    acttime = count = 0
    startt = time.time()
    while acttime < 3:
        callback(content, key, nonce)
        acttime = time.time() - startt
        count += 1
    return acttime, count        


def bench(callback, size, tout=3, multi=True):
    
    content = os.urandom(size)
    key = os.urandom(32)
    nonce = os.urandom(12)
    try:
        callback(content, key, nonce)
    except Exception:
            print(traceback.format_exc())
            return None
    if multi:
        man = manager(callback, tout)
        man.encrypt(content, key, nonce)
        time.sleep(3)
        acttime, count = man.close()
    else:
        acttime, count = _bench(callback, content, key, nonce)
    tput = size * count / (10 ** 6) / acttime
    #print("Function: %s, Multi: %s, Input: %s bytes, throughput: %s Mbs in %ss" % (callback, multi, size, tput, acttime))
    print(";".join([str(callback), str(size), str(tput)]))
    return count


def nacl_pol1305chacha(content, key, nonce):
    aead = AEAD(key)
    # aead.useAESGCM()
    _, _, e1 = aead.encrypt(content, b'',
                            nonce=nonce,
                            pack_nonce_aad=False)
    return e1
    
def nacl_aes256gcm(content, key, nonce):
    aead = AEAD(key)
    aead.useAESGCM()
    _, _, e1 = aead.encrypt(content, b'',
                            nonce=nonce,
                            pack_nonce_aad=False)


def openssl_poly1305chacha(content, key, nonce):
    chacha = ChaCha20Poly1305(key)
    e2 = chacha.encrypt(nonce, content, b'')

def openssl_aes256gcm(content, key, nonce):
    aes = AESGCM(key)
    e2 = aes.encrypt(nonce, content, b'')

def openssl_aes128gcm(content, key, nonce):
    aes = AESGCM(key[:16])
    e2 = aes.encrypt(nonce, content, b'')

def aeadpy_chacha20poly1305(content, key, nonce):
    return aeadpy.encrypt(b"CHACHA20_POLY1305", key, content, nonce, b"")["ciphertext"]

def aeadpy_chacha20poly1305_dec(content, key, nonce):
    return aeadpy.decrypt(b"CHACHA20_POLY1305", key, content, nonce, b"", b"")["plaintext"]
 
def openssl_chacha20poly1305custom(content, key, nonce):
    evp_cipher = backend._lib.EVP_get_cipherbyname(b"chacha20-poly1305")
    # backend.openssl_assert(evp_cipher != backend._ffi.NULL)
    ctx = backend._lib.EVP_CIPHER_CTX_new()
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_CIPHER_CTX_free)
    backend._lib.EVP_CipherInit_ex(ctx, evp_cipher, backend._ffi.NULL, backend._ffi.NULL, backend._ffi.NULL, 1)
    # backend.openssl_assert(res != 0)
    backend._lib.EVP_CIPHER_CTX_set_key_length(ctx, len(key))
    # backend.openssl_assert(res != 0)
    backend._lib.EVP_CIPHER_CTX_ctrl(ctx, backend._lib.EVP_CTRL_AEAD_SET_IVLEN, len(nonce), backend._ffi.NULL)
    # backend.openssl_assert(res != 0)
   
    ####
    
    nonce_ptr = backend._ffi.from_buffer(nonce)
    key_ptr = backend._ffi.from_buffer(key)
    backend._lib.EVP_CipherInit_ex(ctx, backend._ffi.NULL, backend._ffi.NULL, key_ptr, nonce_ptr, 1)
    # backend.openssl_assert(res != 0)
    # aad
    #outlen = backend._ffi.new("int *")
    #buf = backend._ffi.new("unsigned char[]", 0)
    #backend._lib.EVP_CipherUpdate(ctx, buf, outlen, b"", 0)
    # backend.openssl_assert(res != 0)
    #backend._ffi.buffer(buf, outlen[0])[:]

    # _process_aad(backend, ctx, associated_data)
    # data
    outlen = backend._ffi.new("int *")
    buf = backend._ffi.new("unsigned char[]", len(content))
    backend._lib.EVP_CipherUpdate(ctx, buf, outlen, content, len(content))
    # backend.openssl_assert(res != 0)
    processed_data = backend._ffi.buffer(buf, outlen[0])[:]
    
    #processed_data = _process_data(backend, ctx, data)
    outlen = backend._ffi.new("int *")
    backend._lib.EVP_CipherFinal_ex(ctx, backend._ffi.NULL, outlen)
    # backend.openssl_assert(res != 0)
    # backend.openssl_assert(outlen[0] == 0)
    tag_buf = backend._ffi.new("unsigned char[]", 16)
    backend._lib.EVP_CIPHER_CTX_ctrl(ctx, backend._lib.EVP_CTRL_AEAD_GET_TAG, 16, tag_buf)
    # backend.openssl_assert(res != 0)
    tag = backend._ffi.buffer(tag_buf)[:]

    return processed_data + tag

print("running on %s core cpu" % cpu_count())

content = os.urandom(256)
key = os.urandom(32)
nonce = os.urandom(12)
enc1 = aeadpy_chacha20poly1305(content, key, nonce)
enc = nacl_pol1305chacha(content, key, nonce)
dec = aeadpy_chacha20poly1305_dec(enc, key, nonce)

for i in range(6):
    print(backend._ffi.string(backend._lib.OpenSSL_version(i)).decode())
#for cb in openssl_poly1305chacha, nacl_pol1305chacha, openssl_aes128gcm, nacl_aes256gcm, openssl_aes256gcm:
for cb in [aeadpy_chacha20poly1305, nacl_pol1305chacha]:
    for multi in (False, ):
        for size in sizes:
            ret = bench(cb, size, 3, multi)
