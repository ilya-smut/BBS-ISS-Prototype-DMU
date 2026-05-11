"""
Convenience helper for wiring all-local demo and testing environments.

Creates all four orchestrators with LocalLoopbackEndpoints, so that
protocol flows execute in-process with JSON serialization round-trips
to validate the serialization layer.
"""

from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.endpoints.loopback import LocalLoopbackEndpoint
from bbs_iss.endpoints.orchestrator import (
    HolderOrchestrator,
    IssuerOrchestrator,
    VerifierOrchestrator,
    RegistryOrchestrator,
)


def create_local_demo(
    issuer: IssuerInstance,
    holder: HolderInstance,
    verifier: VerifierInstance,
    registry: RegistryInstance,
) -> tuple[HolderOrchestrator, IssuerOrchestrator, VerifierOrchestrator, RegistryOrchestrator]:
    """
    Wire four entity instances into orchestrators connected via
    LocalLoopbackEndpoints.

    Each orchestrator's endpoints wrap the *other* entities, simulating
    network boundaries through JSON serialization round-trips.

    Parameters
    ----------
    issuer : IssuerInstance
        The local Issuer entity.
    holder : HolderInstance
        The local Holder entity.
    verifier : VerifierInstance
        The local Verifier entity.
    registry : RegistryInstance
        The local Registry entity.

    Returns
    -------
    tuple[HolderOrchestrator, IssuerOrchestrator, VerifierOrchestrator, RegistryOrchestrator]
        Four pre-wired orchestrators ready for protocol execution.

    Example
    -------
    >>> issuer = IssuerInstance()
    >>> holder = HolderInstance()
    >>> verifier = VerifierInstance()
    >>> registry = RegistryInstance()
    >>> holder_orch, issuer_orch, verifier_orch, registry_orch = create_local_demo(
    ...     issuer, holder, verifier, registry
    ... )
    >>> # Register issuer
    >>> trail = issuer_orch.register_with_registry()
    >>> # Sync caches
    >>> holder_orch.sync_registry()
    >>> verifier_orch.sync_registry()
    >>> # Execute issuance
    >>> trail = holder_orch.execute_issuance("Issuer-Name", attributes, "my-cred")
    """
    # Create loopback endpoints — each wraps a remote entity
    registry_ep = LocalLoopbackEndpoint("registry", registry)
    issuer_ep = LocalLoopbackEndpoint("issuer", issuer)
    holder_ep = LocalLoopbackEndpoint("holder", holder)
    verifier_ep = LocalLoopbackEndpoint("verifier", verifier)

    # Wire orchestrators
    holder_orch = HolderOrchestrator(
        holder,
        issuer=issuer_ep,
        verifier=verifier_ep,
        registry=registry_ep,
    )
    issuer_orch = IssuerOrchestrator(
        issuer,
        registry=registry_ep,
    )
    verifier_orch = VerifierOrchestrator(
        verifier,
        holder=holder_ep,
        registry=registry_ep,
    )
    registry_orch = RegistryOrchestrator(registry)

    return holder_orch, issuer_orch, verifier_orch, registry_orch
