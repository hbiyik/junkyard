'''
Created on Oct 23, 2020

@author: boogie
'''

from ipv8.community import Community
from ipv8.messaging.serialization import default_serializer

from ssp.session import SessionManager, Session, Connection, STATUS_CONNECTED, STATUS_CONNECTING, STATUS_DISCONNECTED, SESSION_TIMEOUT
from ssp.packets import StreamConnectRequest, StreamDataRequest, StreamDisconnectRequest, StreamResponse
import os
from ipv8.lazy_community import lazy_wrapper

from ssp import exceptions


class SspCommunity(Community):
    sessman = SessionManager()
    community_id = os.urandom(20)
    
    def __init__(self, my_peer, endpoint, network):
        super().__init__(my_peer, endpoint, network)
        self.serializer = default_serializer
        # {peerid: sessid: connection}
        self.add_message_handler(0, self.on_streamresponse)
        self.add_message_handler(1, self.on_streamconnectrequest)
        self.add_message_handler(2, self.on_streamdatarequest)
        self.add_message_handler(3, self.on_streamdisconnectrequest)
        
    def _sendresponse(self, peer, request):
        session = self.sessman.get(peer.mid, request.id)
        ack = session is not None and request.sequence == (session.sequence + 1) % 65536
        self.ez_send(peer, StreamResponse(session.id,
                                          session.sequence,
                                          ack,
                                          request.msg_id))
        session.nextsequence()
        return ack

  
    @lazy_wrapper(StreamConnectRequest)  
    def on_streamconnectrequest(self, peer, request):
        session = Session(peer, request.attributes, request.timeout)
        session.peersequence = request.sequence
        ack = self.on_newconnection(session)
        if ack:
            try:
                self.sessman.add(session)
            except exceptions.SessionAlreadyAvailable:
                self.sessman.remove(session)
                self.logger.info(f"Session id: {request.session}, peer: {peer} is already available, dropping request")
                ack = False
        session.nextpeersequence()
        self.ez_send(peer, StreamResponse(session.id,
                                          session.sequence,
                                          ack,
                                          request.msg_id))

    @lazy_wrapper(StreamDisconnectRequest)
    def on_streamdisconnectrequest(self, peer, request):
        if self._sendresponse(peer, request):
            pass
            # self.sessman.remove(session)
    
    @lazy_wrapper(StreamDataRequest)  
    async def on_streamdatarequest(self, peer, request):
        if self._sendresponse(peer, request):
            pass
            # timeout here?
            #event = await session.readevents.get()
            #event.set(request.payload)

    @lazy_wrapper(StreamResponse)
    async def on_streamresponse(self, peer, response):
        session = self.sessman.get(peer.mid, response.session)
        if response.sequence != session.sequence:
            raise exceptions.SessionInvalidSequence(session, response.sequence)
        # timeout here?
        # buffering here?
        session.responseevent.set(response)

    def on_newconnection(self, session):
        # mevlana mode
        return True

    async def connection(self, peer, attrs, timeout):
        timeout = timeout or SESSION_TIMEOUT
        session = Session(peer, attrs, timeout)
        return Connection(self, session)

    def on_start(self):
        async def print_peers():
            print("I am:", self.my_peer, "\nI know:", [str(p) for p in self.get_peers()])

        self.register_task("print_peers", print_peers, interval=5.0, delay=0)
        
    def disconnect(self, peer):
        pass
    