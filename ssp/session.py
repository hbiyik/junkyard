'''
Created on Oct 23, 2020

@author: boogie
'''

from asyncio import Queue, get_event_loop
import random
import collections
from ssp import exceptions
from ssp import packets

STATUS_CONNECTING = 0
STATUS_CONNECTED = 1
STATUS_DISCONNECTED = 2
STATUS_TIMEDOUT = 3

SESSION_TIMEOUT = 10


class SessionManager:
    # mid: sessid: session
    sessions = {}

    def add(self, session):
        if self.has(session):
            raise exceptions.SessionAlreadyAvailable(session)
        if session.peer.mid not in self.sessions:
            self.sessions[session.peer.mid] = {}
        
        if session.id is None: 
            if len(self.sessions[session.peer.mid]) == 65536:
                raise exceptions.SessionFull(session)
            session.id = random.choice(list(set(range(65535)) - set(self.sessions[session.peer.mid].keys())))

        self.sessions[session.peer.mid][session.id] = session
    
    def remove(self, session):
        if self.has(session):
            self.sessions[session.peer.mid].pop(session.id)
            return True
        return False
    
    def _has(self, mid, sessid):
        return mid in self.sessions and sessid in self.sessions[mid]
    
    def has(self, session):
        return self._has(session.peer.mid, session.id)
    
    def get(self, mid, sessid):
        if self._has(mid, sessid):
            return self.sessions[mid][sessid]
        raise exceptions.SessionNotAvailable(sessid, mid)


class Session:
    def __init__(self, peer, attrs, timeout):
        self.timeout = timeout
        self.peer = peer
        self.peersequence = -1
        self.sequence -1
        self.attributes = attrs
        self.id = None
        self.requestevent = SessionEvent()
        self.responseevent = SessionEvent() 
        self.readevents = Queue()
        self.status = STATUS_DISCONNECTED
        
    def __str__(self):
        return f"id       : f{self.id}"\
               f"status   : f{self.status}"\
               f"sequence : f{self.sequence}"\
               f"peer     : f{self.peer}"\
               f"peer-seq : f{self.peerseq}"\
               f"attrs    : f{self.attrs}"\
        
    def nextsequence(self):
        self.sequence = ( self.sequence + 1 ) % 65536

    def nextpeersequence(self):
        self.peersequence = ( self.peersequence + 1 ) % 65536


class Connection:
    def __init__(self, community, session, maxchunk=100):
        self.__community = community
        self.session = session
        self.maxchunk = maxchunk
        self.maxretransmits = 5

    async def __aenter__(self):
        return await self.open()
    
    async def __aexit__(self, _typ, _val, _tb):
        return await self.close()
    
    @property
    def isconnected(self):
        return self.session.status == STATUS_CONNECTED
    
    @property
    def status(self):
        return self.session.status
        
    async def _checkstatus(self, *notallowed, wait=True):
        if self.session in notallowed:
            raise exceptions.SessionUnexpectedStatus(self.session)
        elif wait and self.session.status == STATUS_CONNECTING:
            while True:
                await self.session.statusevent.get(notallowed, False)
                await self._checkstatus()

    async def read(self):
        # read from peer
        await self._checkstatus(STATUS_DISCONNECTED, SESSION_TIMEOUT)
        await chunk = self.session.readevents.get()
        return chunk
    
    async def write(self, data):
        # write to peer
        await self._checkstatus(STATUS_DISCONNECTED, SESSION_TIMEOUT)
        index = 0
        transmit = 1
        retransmisson = False
        size = len(data)
        cursor = index * self.maxchunk
        while True:
            if transmit == self.maxretransmits:
                await self.close(False)
                raise exceptions.SessionMaxRetry(self.session)
            if cursor > size:
                break
            if not retransmisson:
                index += 1
                nextcursor = index * self.maxchunk
                self.session.nextsequence()
            self.__comunity.ez_send(self.session.peer, packets.StreamDataRequest(self.session.id,
                                                                                 self.session.sequence,
                                                                                 data[cursor, nextcursor]))
            response = await self.session.responseevent.wait()
            if response.request == packets.StreamDataRequest.msg_id:
                if response.ack:
                    retransmisson = False
                else:
                    retransmisson = True
                    transmit += 1
                    continue
            else:
                await self.close(False)
                raise exceptions.SessionInvalidResponse(self.session, response)
            cursor = nextcursor
            pass
         
    
    async def open(self):
        # initiate a connect request, if session is not connected
        await self._checkstatus(STATUS_CONNECTED, STATUS_CONNECTING, wait=False)
        self.__community.sessman.add(self.session)
        self.session.status = STATUS_CONNECTING
        self.session.nextsequence()
        self.__comunity.ez_send(self.session.peer, packets.StreamConnectRequest(self.session.id,
                                                                                self.session.sequence,
                                                                                self.session.timeout,
                                                                                self.session.attributes))
        response = await self.session.responseevent.wait()
        if response.request == packets.StreamConnectRequest.msg_id:
            if response.ack:
                self.session.status = STATUS_CONNECTED
                return self
            else:
                self.session.status = STATUS_DISCONNECTED
                self.__community.sessman.remove(self.session)
    
    async def close(self, confirm=True):
        # initiate a disconnect request if session is already connected
        await self._checkstatus(STATUS_DISCONNECTED, STATUS_TIMEDOUT)
        self.__comunity.ez_send(self.session.peer, packets.StreamDisconnectRequest(self.session.id,
                                                                                   self.session.attributes))
        self.session.nextsequence()
        if confirm:
            response = await self.session.responseevent.wait()
            if response.request == packets.StreamDisconnectRequest.msg_id:
                self.session.status = STATUS_DISCONNECTED
                self.__community.sessman.remove(self.session)
                return True
        return False


class SessionEvent:
    def __init__(self):
        self._waiters = collections.deque()

    def set(self, result):
        for fut in self._waiters:
            if not fut.done():
                fut.set_result(result)

    async def wait(self):
        fut = get_event_loop().create_future()
        self._waiters.append(fut)
        ret = await fut()
        self._waiters.remove(fut)
        return ret
