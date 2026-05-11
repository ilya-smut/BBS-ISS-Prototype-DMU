import json
import logging
from threading import Thread

from flask import Flask, request as flask_request, Response

import bbs_iss.interfaces.requests_api as api
from bbs_iss.demo.demo_configuration import DefaultRoutes
from bbs_iss.endpoints.listener import Listener
from bbs_iss.entities.entity import Entity


# Suppress Flask/Werkzeug request logs in demo output
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _json_response(data: dict, status: int = 200) -> Response:
    """Return a JSON response without key sorting (critical for BBS+)."""
    return Response(
        json.dumps(data, sort_keys=False),
        status=status,
        mimetype="application/json",
    )


class FlaskListener(Listener):
    """
    Flask-based server that receives protocol messages at /process
    and dispatches them appropriately.

    For generic requests (issuance, registry), the listener calls
    entity.process_request() directly.

    For requests that require orchestrator-level handling (VP_REQUEST,
    FORWARD_VP), the listener delegates to the orchestrator.

    Parameters
    ----------
    entity : Entity
        The local entity.
    host : str
        Bind address.
    port : int
        Bind port.
    orchestrator : object, optional
        The entity's orchestrator. Required for VP_REQUEST (Holder)
        and FORWARD_VP (Verifier) handling.
    presentation_config : dict, optional
        Pre-configured defaults for Holder VP auto-response:
        {"vc_name": str, "always_hidden_keys": list[str]}.
    """

    def __init__(
        self,
        entity: Entity,
        host: str = "0.0.0.0",
        port: int = 5000,
        orchestrator=None,
        presentation_config: dict = None,
    ):
        super().__init__(entity, host, port)
        self.orchestrator = orchestrator
        self.presentation_config = presentation_config or {}
        self._app = Flask(f"listener-{port}")
        self._server_thread = None
        self._setup_routes()

    def _setup_routes(self):
        @self._app.route(DefaultRoutes.PROCESS, methods=["POST"])
        def process():
            req = api.Request.from_dict(flask_request.get_json())

            # ── VP_REQUEST: queue in Holder orchestrator ──────────────
            if req.request_type == api.RequestType.VP_REQUEST:
                if self.orchestrator is None:
                    return "", 501  # Not configured for VP handling
                self.orchestrator.pending_requests.append(req)
                return "", 200

            # ── FORWARD_VP: delegate to Verifier orchestrator ────────
            if req.request_type == api.RequestType.FORWARD_VP:
                if self.orchestrator is None:
                    return "", 501
                try:
                    result = self.orchestrator.complete_presentation(req)
                    self.orchestrator.verification_results.append(result)
                    valid = result[0] if isinstance(result, tuple) else False
                    return _json_response({"valid": valid})
                except Exception as e:
                    return _json_response({"error": str(e)}, status=500)

            # ── Generic: entity-level dispatch ───────────────────────
            try:
                result = self.entity.process_request(req)
            except Exception as e:
                return _json_response({"error": str(e)}, status=500)

            if isinstance(result, api.Request):
                return _json_response(json.loads(result.to_json()))
            else:
                return "", 200

    def start(self):
        """Start Flask in a daemon thread (non-blocking)."""
        self._server_thread = Thread(
            target=self._app.run,
            kwargs={"host": self.host, "port": self.port, "debug": False},
            daemon=True,
        )
        self._server_thread.start()

    def stop(self):
        """Daemon threads terminate with the main process."""
        pass
