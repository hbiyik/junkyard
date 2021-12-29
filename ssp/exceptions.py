'''
Created on Oct 23, 2020

@author: boogie
'''

class SessionException(Exception):
    def __init__(self, session):
        self.message = session
        super().__init__(self.message)

    def __str__(self):
        return self.message


class SessionFull(SessionException):
    pass

class SessionMaxRetry(SessionException):
    pass

class SessionAlreadyAvailable(SessionException):
    pass

class SessionInvalidResponse(SessionException):
    def __init__(self, session, response):
        self.message = f"Session:{session}, response: {response}"
        super().__init__(self.message)

class SessionNotAvailable(SessionException):
    def __init__(self, sessid, mid):
        self.message = f"Session:{sessid}, mid: {mid}"
        super().__init__(self.message)

class SessionInvalidSequence(SessionException):
    def __init__(self, session, sequence):
        self.message = f"Session:{session}, sequence: {sequence}"
        super().__init__(self.message)

class SessionUnexpectedStatus(SessionException):
    pass
