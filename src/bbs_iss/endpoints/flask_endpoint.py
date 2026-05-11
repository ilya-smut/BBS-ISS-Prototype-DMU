import json
import requests as http_requests
import bbs_iss.interfaces.requests_api as api
from bbs_iss.demo.demo_configuration import DefaultRoutes, DEFAULT_HTTP_TIMEOUT_SECONDS
from bbs_iss.endpoints.endpoint import Endpoint


class FlaskEndpoint(Endpoint):
    """
    HTTP transport adapter using the `requests` library.

    Sends protocol messages as JSON to a remote entity's Flask server
    and deserialises responses.
    """

    def __init__(self, name: str, target_url: str, timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS):
        """
        Parameters
        ----------
        name : str
            Human-readable identifier (e.g. "issuer", "registry").
        target_url : str
            Base URL of the remote Flask server (e.g. "http://localhost:5001").
        timeout : int
            HTTP request timeout in seconds. Defaults to DEFAULT_HTTP_TIMEOUT_SECONDS.
        """
        super().__init__(name, target_url)
        self._response = None
        self._timeout = timeout

    def send(self, request: api.Request) -> None:
        """
        Serialize the request and POST it to the remote entity's
        /process endpoint.
        """
        json_str = request.to_json()
        self._response = http_requests.post(
            f"{self.target_url}{DefaultRoutes.PROCESS}",
            json=json.loads(json_str),
            headers={"Content-Type": "application/json"},
            timeout=self._timeout,
        )
        self._response.raise_for_status()

    def receive(self) -> api.Request:
        """
        Deserialize the response from the last send() call.

        If the response contains a serialised Request object, it is
        reconstructed via from_dict. Otherwise the raw dict is returned
        (e.g. for simple acknowledgments).
        """
        data = self._response.json()
        if "request_type" in data:
            return api.Request.from_dict(data)
        return data
