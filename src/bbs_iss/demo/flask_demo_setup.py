"""
Convenience helper for wiring a networked Flask demo environment.

Creates all four orchestrators with FlaskEndpoints and starts
FlaskListeners on separate ports, so that protocol flows execute
over real HTTP transport.
"""

import time

from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.endpoints.flask_endpoint import FlaskEndpoint
from bbs_iss.endpoints.flask_listener import FlaskListener
from bbs_iss.endpoints.orchestrator import (
    HolderOrchestrator,
    IssuerOrchestrator,
    VerifierOrchestrator,
    RegistryOrchestrator,
)
from bbs_iss.demo.demo_configuration import DefaultPorts


def create_flask_demo(
    issuer: IssuerInstance,
    holder: HolderInstance,
    verifier: VerifierInstance,
    registry: RegistryInstance,
    issuer_port: int = DefaultPorts.ISSUER,
    verifier_port: int = DefaultPorts.VERIFIER,
    registry_port: int = DefaultPorts.REGISTRY,
    holder_port: int = DefaultPorts.HOLDER,
) -> tuple[HolderOrchestrator, IssuerOrchestrator, VerifierOrchestrator, RegistryOrchestrator]:
    """
    Wire four entity instances for networked demo.

    Each server-side entity runs a Flask listener on a dedicated port.
    Orchestrators communicate via FlaskEndpoints (HTTP POST).

    Topology (single machine)::

        Registry:  http://localhost:{registry_port}/process
        Issuer:    http://localhost:{issuer_port}/process
        Verifier:  http://localhost:{verifier_port}/process
        Holder:    http://localhost:{holder_port}/process

    Parameters
    ----------
    issuer, holder, verifier, registry : entity instances
    issuer_port, verifier_port, registry_port, holder_port : int
        Port assignments for each Flask server.

    Returns
    -------
    tuple[HolderOrchestrator, IssuerOrchestrator, VerifierOrchestrator, RegistryOrchestrator]
    """
    base = "http://localhost"

    # ── 1. Create FlaskEndpoints (client handles) ────────────────────
    registry_ep_for_holder  = FlaskEndpoint("registry", f"{base}:{registry_port}")
    registry_ep_for_issuer  = FlaskEndpoint("registry", f"{base}:{registry_port}")
    registry_ep_for_verifier = FlaskEndpoint("registry", f"{base}:{registry_port}")
    issuer_ep   = FlaskEndpoint("issuer",   f"{base}:{issuer_port}")
    verifier_ep = FlaskEndpoint("verifier", f"{base}:{verifier_port}")
    holder_ep   = FlaskEndpoint("holder",   f"{base}:{holder_port}")

    # ── 2. Create Orchestrators ──────────────────────────────────────
    holder_orch = HolderOrchestrator(
        holder,
        issuer=issuer_ep,
        verifier=verifier_ep,
        registry=registry_ep_for_holder,
    )
    issuer_orch = IssuerOrchestrator(
        issuer,
        registry=registry_ep_for_issuer,
    )
    verifier_orch = VerifierOrchestrator(
        verifier,
        holder=holder_ep,
        registry=registry_ep_for_verifier,
    )
    registry_orch = RegistryOrchestrator(registry)

    # ── 3. Create and start Listeners ────────────────────────────────
    registry_listener = FlaskListener(registry, port=registry_port)
    issuer_listener   = FlaskListener(issuer,   port=issuer_port)
    verifier_listener = FlaskListener(
        verifier, port=verifier_port, orchestrator=verifier_orch,
    )
    holder_listener = FlaskListener(
        holder, port=holder_port, orchestrator=holder_orch,
    )

    registry_listener.start()
    issuer_listener.start()
    verifier_listener.start()
    holder_listener.start()

    # Brief pause to let all servers bind
    time.sleep(0.5)

    return holder_orch, issuer_orch, verifier_orch, registry_orch
