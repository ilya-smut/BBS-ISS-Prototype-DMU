from abc import ABC, abstractmethod
import bbs_iss.interfaces.requests_api as api


class Endpoint(ABC):
    """
    Transport adapter for communicating with a remote entity.

    An Endpoint is a proxy handle — it does not contain entity logic.
    It serializes outgoing requests, transmits them over a transport
    layer, and deserializes incoming responses.

    Concrete subclasses implement the actual transport mechanism
    (HTTP/Flask, WebSocket, etc.).
    """

    def __init__(self, name: str, target_url: str = None):
        """
        Parameters
        ----------
        name : str
            Human-readable identifier for this endpoint (e.g. "issuer", "registry").
        target_url : str, optional
            Network address of the remote entity. None for non-network endpoints.
        """
        self.name = name
        self.target_url = target_url

    @abstractmethod
    def send(self, request: api.Request) -> None:
        """
        One-way: serialize the request and transmit it.
        No response is expected from the remote side.
        """
        ...

    @abstractmethod
    def receive(self) -> api.Request:
        """
        Block until a response arrives from the remote entity,
        then deserialize and return it.
        """
        ...

    def exchange(self, request: api.Request) -> api.Request:
        """
        Request-response pattern: send a request and wait for the response.

        This is the default synchronous interaction mode.
        Use send() directly when no response is expected (fire-and-forget).
        """
        self.send(request)
        return self.receive()
