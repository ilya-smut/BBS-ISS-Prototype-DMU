import bbs_iss.interfaces.requests_api as api
from bbs_iss.endpoints.endpoint import Endpoint
from bbs_iss.entities.entity import Entity


class LocalLoopbackEndpoint(Endpoint):
    """
    Testing endpoint that wraps a local Entity instance.

    Simulates a network boundary by forcing a full JSON serialization
    round-trip on every message. This validates that the serialization
    layer (to_json / from_json) is correct for all request types,
    without requiring actual network infrastructure.

    Usage:
        issuer_ep = LocalLoopbackEndpoint("issuer", issuer_instance)
        response = issuer_ep.exchange(some_request)
    """

    def __init__(self, name: str, entity: Entity):
        super().__init__(name, target_url=None)
        self._entity = entity
        self._pending = None

    def send(self, request: api.Request) -> None:
        """
        Serialize the request to JSON, deserialize it back (simulating
        network transit), pass it to the wrapped entity's process_request(),
        and store the response for later retrieval via receive().
        """
        # Serialize → deserialize to simulate network boundary
        json_str = request.to_json()
        deserialized = api.Request.from_json(json_str)

        # Process through the local entity
        response = self._entity.process_request(deserialized)

        # If response is a Request subclass, round-trip it too
        if isinstance(response, api.Request):
            self._pending = api.Request.from_json(response.to_json())
        else:
            # Non-Request responses (e.g. bool, tuple) pass through directly
            self._pending = response

    def receive(self) -> api.Request:
        """
        Return the stored response from the last send() call.
        """
        result = self._pending
        self._pending = None
        return result
