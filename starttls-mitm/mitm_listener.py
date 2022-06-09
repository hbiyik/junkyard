#!/usr/bin/env python

import sys
import socket
import ssl
from threading import Thread
from scapy.packet import Raw
from scapy.layers import l2, inet
from scapy.utils import PcapWriter
from select import select

HOST = '0.0.0.0'
DPORT = 389
SPORT = 12345
BUFSIZE = 409600

pktdump = PcapWriter("banana.pcap", append=False, sync=True)

PROTO = ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2


def wrap_sockets(client_sock, server_sock, certfile, keyfile, cafile):
    return (ssl.wrap_socket(client_sock,
                            server_side=True,
                            suppress_ragged_eofs=True,
                            certfile=certfile,
                            keyfile=keyfile,
                            ca_certs=cafile,
                            do_handshake_on_connect=False),
            ssl.wrap_socket(
                server_sock,
                suppress_ragged_eofs=True,
                ca_certs=cafile))


def do_relay(client_sock, server_sock, certfile, keyfile, cafile):
    server_sock.settimeout(5.0)
    client_sock.settimeout(5.0)
    print('RELAYING')
    while 1:
        if not isinstance(client_sock, ssl.SSLSocket):
            maybe_handshake = client_sock.recv(BUFSIZE, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            if maybe_handshake.startswith(b'\x16\x03'):
                print('Wrapping sockets.')
                client_sock, server_sock = wrap_sockets(client_sock, server_sock, certfile, keyfile, cafile)
        receiving, _, _ = select([client_sock, server_sock], [], [])
        if client_sock in receiving:
            p = client_sock.recv(BUFSIZE)
            if not p == b"":
                server_sock.send(p)
                pktdump.write(l2.Ether() / inet.IP(dst="1.2.3.4") / inet.UDP(sport=SPORT, dport=DPORT) / Raw(load=p))
                print("C->S", len(p), repr(p))

            p = server_sock.recv(BUFSIZE)
            if not p == b"":
                client_sock.send(p)
                pktdump.write(l2.Ether() / inet.IP(src="1.2.3.4") / inet.UDP(sport=DPORT, dport=SPORT) / Raw(load=p))
                print("S->C", len(p), repr(p))


def child(clientsock, target, certfile, keyfile, cafile):
    targetsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    targetsock.connect((target, DPORT))
    do_relay(clientsock, targetsock, certfile, keyfile, cafile)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        sys.exit('Usage: %s TARGETHOST <KEYFILE> <CERTFILE>\n' % sys.argv[0])
    target = sys.argv[1]
    keyfile = sys.argv[2]
    certfile = sys.argv[3]
    cafile = sys.argv[4]
    myserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myserver.bind((HOST, DPORT))
    myserver.listen(2)
    print('LISTENER ready on port', DPORT)
    while 1:
        client, addr = myserver.accept()
        print('CLIENT CONNECT from:', addr)
        t = Thread(target=child, args=(client, target, certfile, keyfile, cafile))
        t.start()
        t.join()
