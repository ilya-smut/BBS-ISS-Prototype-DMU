from abc import ABC, abstractmethod
from bbs_iss.entities.entity import Entity


class Listener(ABC):
    """
    Server-side counterpart of Endpoint.

    A Listener receives incoming protocol messages from remote
    Orchestrators, routes them to the local Entity's process_request(),
    and sends the response back over the transport layer.

    Concrete subclasses implement the actual server mechanism
    (e.g. Flask routes, WebSocket handlers).

    This is a stub — concrete implementations will be added when
    the transport library is selected.
    """

    def __init__(self, entity: Entity, host: str = "0.0.0.0", port: int = 5000):
        """
        Parameters
        ----------
        entity : Entity
            The local entity whose process_request() will handle
            incoming messages.
        host : str
            Bind address for the server.
        port : int
            Bind port for the server.
        """
        self.entity = entity
        self.host = host
        self.port = port

    @abstractmethod
    def start(self):
        """Start the listener server."""
        ...

    @abstractmethod
    def stop(self):
        """Stop the listener server."""
        ...
