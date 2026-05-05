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

class HolderNotInInteraction(Exception):
    def __init__(self, message="Holder is not in an active interaction"):
        self.message = message
        super().__init__(self.message)

class FreshnessValueError(Exception):
    def __init__(self, message="Invalid freshness value"):
        self.message = message
        super().__init__(self.message)

class HolderStateError(Exception):
    def __init__(self, message="Invalid holder state", state=None):
        self.state = state
        if state is not None:
            state_details = "\n".join(
                f"  {key}: {value!r}" for key, value in vars(state).items()
            )
            message = f"{message}\nHolder state at time of error:\n{state_details}"
        self.message = message
        super().__init__(self.message)

class ProofValidityError(Exception):
    def __init__(self, message="Invalid proof"):
        self.message = message
        super().__init__(self.message)

class VerifierNotInInteraction(Exception):
    def __init__(self, message="Verifier is not in an active interaction"):
        self.message = message
        super().__init__(self.message)

class VerifierStateError(Exception):
    def __init__(self, message="Invalid verifier state", state=None):
        self.state = state
        if state is not None:
            state_details = "\n".join(
                f"  {key}: {value!r}" for key, value in vars(state).items()
            )
            message = f"{message}\nVerifier state at time of error:\n{state_details}"
        self.message = message
        super().__init__(self.message)

