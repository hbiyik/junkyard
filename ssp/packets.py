'''
Created on Oct 23, 2020

@author: boogie
'''
from ipv8.messaging.lazy_payload import Payload, VariablePayload, vp_compile

@vp_compile    
class StreamResponse(Payload):
    msg_id = 0
    format_list = ['H', "H", 'bits', 'bits']
    names = ['session', 'sequence', 'ack', 'request']


@vp_compile
class StreamConnectRequest(Payload):
    msg_id = 1
    format_list = ['H', 'H', 'H', 'varlenI']
    names = ['session', 'sequence', 'timeout', 'attributes',]

@vp_compile
class StreamDataRequest(Payload):
    msg_id = 2
    format_list = ['H', "L", 'raw']
    names = ['session', 'sequence', 'payload']

@vp_compile
class StreamDisconnectRequest(Payload):
    msg_id = 3
    format_list = ['H']
    names = ['session']
