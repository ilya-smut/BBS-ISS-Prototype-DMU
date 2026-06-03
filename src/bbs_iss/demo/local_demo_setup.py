

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
    # Create loopback endpoints
    registry_ep = LocalLoopbackEndpoint("registry", registry)
    issuer_ep = LocalLoopbackEndpoint("issuer", issuer)
    holder_ep = LocalLoopbackEndpoint("holder", holder)
    verifier_ep = LocalLoopbackEndpoint("verifier", verifier)


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
