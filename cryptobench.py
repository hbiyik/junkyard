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
import evp


from libnacl.aead import AEAD
from multiprocessing import Process, Pipe, cpu_count

k1 = 2 ** 17
sizes = [2 ** 4, 2 ** 8, 2 ** 12, 2 ** 16, k1, int(k1 * 1.5), k1 * 2, k1 * 3, k1 * 4, k1 * 5, k1 * 6, k1 * 7, k1 * 8]
profiler = pprofile.Profile()

_ENCRYPT = 1
_DECRYPT = 0

Evp = evp.Aead()


def worker(i, conn, callback, tout):
    count = acttime = 0
    startt = time.time()
    args = conn.recv()
    while acttime < tout:
        callback(*args)
        count += 1
        acttime = time.time() - startt
    conn.send((acttime, count))


class manager:
    def __init__(self, callback, timeout):
        self.pipes = []
        self.wcount = cpu_count()
        self.cb = callback
        self.p = []
        for i in range(self.wcount):
            parent_conn, child_conn = Pipe()
            self.pipes.append(parent_conn)
            p = Process(target=worker, args=[i, child_conn, callback, timeout], name=str(i))
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
            


def _bench(callback, content, key, nonce, tout):
    acttime = count = 0
    startt = time.time()
    while acttime < tout:
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
        acttime, count = _bench(callback, content, key, nonce, tout)
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

def asyncaead_chacha20poly1305_enc(content, key, nonce):
    return Evp.encrypt(key, content, nonce, b"")


print("running on %s core cpu" % cpu_count())

content = os.urandom(256)
key = os.urandom(32)
nonce = os.urandom(12)
enc = nacl_pol1305chacha(content, key, nonce)

for multi in (False, True):
    for cb in [asyncaead_chacha20poly1305_enc, nacl_pol1305chacha]:
        for size in sizes:
            ret = bench(cb, size, 3, multi)
