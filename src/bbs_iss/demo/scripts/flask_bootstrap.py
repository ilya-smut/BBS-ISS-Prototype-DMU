from bbs_iss.demo.demo_configuration import DefaultEntityNames, DefaultPorts
from bbs_iss.endpoints.flask_listener import FlaskListener
from bbs_iss.endpoints.flask_endpoint import FlaskEndpoint
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.endpoints.orchestrator import (
    HolderOrchestrator,
    IssuerOrchestrator,
    VerifierOrchestrator,
    RegistryOrchestrator,
)


_DEFAULT_BASE = "http://localhost"


def holder_bootstrap(
    holder_port: int = DefaultPorts.HOLDER,
    issuer_base: str = _DEFAULT_BASE,
    issuer_port: int = DefaultPorts.ISSUER,
    verifier_base: str = _DEFAULT_BASE,
    verifier_port: int = DefaultPorts.VERIFIER,
    registry_base: str = _DEFAULT_BASE,
    registry_port: int = DefaultPorts.REGISTRY,
) -> HolderOrchestrator:
    registry = FlaskEndpoint(name=DefaultEntityNames.REGISTRY, target_url=f"{registry_base}:{registry_port}")
    issuer = FlaskEndpoint(name=DefaultEntityNames.ISSUER, target_url=f"{issuer_base}:{issuer_port}")
    verifier = FlaskEndpoint(name=DefaultEntityNames.VERIFIER, target_url=f"{verifier_base}:{verifier_port}")

    holder = HolderInstance()
    holder_orch = HolderOrchestrator(entity=holder, registry=registry, issuer=issuer, verifier=verifier)
    holder_listener = FlaskListener(entity=holder, host="0.0.0.0", port=holder_port, orchestrator=holder_orch)
    holder_listener.start()
    return holder_orch


def issuer_bootstrap(
    name: str = DefaultEntityNames.ISSUER,
    issuer_port: int = DefaultPorts.ISSUER,
    registry_base: str = _DEFAULT_BASE,
    registry_port: int = DefaultPorts.REGISTRY,
) -> IssuerOrchestrator:
    registry = FlaskEndpoint(name=DefaultEntityNames.REGISTRY, target_url=f"{registry_base}:{registry_port}")

    issuer = IssuerInstance()
    issuer.set_issuer_parameters({"issuer": name})
    issuer_orch = IssuerOrchestrator(entity=issuer, registry=registry)
    issuer_listener = FlaskListener(entity=issuer, host="0.0.0.0", port=issuer_port)
    issuer_listener.start()
    return issuer_orch


def verifier_bootstrap(
    verifier_port: int = DefaultPorts.VERIFIER,
    holder_base: str = _DEFAULT_BASE,
    holder_port: int = DefaultPorts.HOLDER,
    registry_base: str = _DEFAULT_BASE,
    registry_port: int = DefaultPorts.REGISTRY,
) -> VerifierOrchestrator:
    registry = FlaskEndpoint(name=DefaultEntityNames.REGISTRY, target_url=f"{registry_base}:{registry_port}")
    holder = FlaskEndpoint(name=DefaultEntityNames.HOLDER, target_url=f"{holder_base}:{holder_port}")

    verifier = VerifierInstance()
    verifier_orch = VerifierOrchestrator(entity=verifier, holder=holder, registry=registry)
    verifier_listener = FlaskListener(entity=verifier, host="0.0.0.0", port=verifier_port, orchestrator=verifier_orch)
    verifier_listener.start()
    return verifier_orch


def registry_bootstrap(
    registry_port: int = DefaultPorts.REGISTRY,
) -> RegistryOrchestrator:
    registry = RegistryInstance()
    registry_orch = RegistryOrchestrator(entity=registry)
    registry_listener = FlaskListener(entity=registry, host="0.0.0.0", port=registry_port)
    registry_listener.start()
    return registry_orch
