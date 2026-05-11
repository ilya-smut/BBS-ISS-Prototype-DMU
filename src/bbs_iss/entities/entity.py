from abc import ABC, abstractmethod
import bbs_iss.interfaces.requests_api as api


class Entity(ABC):
    """
    Base class for all BBS-ISS protocol entities.
    
    Provides a common interface for protocol message processing.
    Every entity in the system (Issuer, Holder, Verifier, Registry)
    must implement this contract.
    """

    @abstractmethod
    def process_request(self, request: api.Request) -> api.Request | object:
        """
        Process an incoming protocol request and return a response.
        
        Each entity defines its own dispatch logic based on the
        request's type. The return type varies — it may be another
        Request object (to be forwarded), a result value, or an
        ErrorResponse on failure.
        """
        ...

    @property
    @abstractmethod
    def available(self) -> bool:
        """Whether the entity is idle and can accept new interactions."""
        ...

    @abstractmethod
    def reset(self):
        """Force-reset entity state, cancelling any active interaction."""
        ...
