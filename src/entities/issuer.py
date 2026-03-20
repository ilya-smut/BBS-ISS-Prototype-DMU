from enum import Enum
import os

class Issuer:

    class IssuanceRequestType(Enum):
        ISSUANCE = 1
        RE_ISSUANCE = 2
        BLIND_SIGN = 3
    
    class Interaction:
        def __init__(self):
            self.freshness = None 

    
    def __init__(self):
        pass

    def process_request(self, request: IssuanceRequestType):
        pass

    def gen_nonce(self):
        return os.urandom(32)

    def blind_sign(self):
        pass
    