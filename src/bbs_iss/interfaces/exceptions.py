class AttributesNotCommitted(Exception):
    def __init__(self, message="Attributes not committed"):
        self.message = message
        super().__init__(self.message)

class NoBlindedAttributes(Exception):
    def __init__(self, message="No blinded attributes"):
        self.message = message
        super().__init__(self.message)

class NoRevealedAttributes(Exception):
    def __init__(self, message="No revealed attributes"):
        self.message = message
        super().__init__(self.message)

class IssuerNotAvailable(Exception):
    def __init__(self, message="Issuer is processing another request"):
        self.message = message
        super().__init__(self.message)

class FreshnessValueError(Exception):
    def __init__(self, message="Invalid freshness value"):
        self.message = message
        super().__init__(self.message)

