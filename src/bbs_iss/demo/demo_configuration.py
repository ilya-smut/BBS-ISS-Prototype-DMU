"""
Default configuration presets for demo environments.

Centralises demo-specific constants (routes, ports, entity names)
so they can be changed in one place.
"""


class DefaultRoutes:
    """Standardised URL paths for entity Flask servers."""
    PROCESS = "/process"


class DefaultPorts:
    """Default port assignments for Flask demo servers."""
    ISSUER = 5001
    VERIFIER = 5002
    REGISTRY = 5003
    HOLDER = 5004


class DefaultEntityNames:
    """Default entity names used in demo scenarios."""
    ISSUER = "Test-University"
    HOLDER = "Demo-Holder"
    VERIFIER = "Demo-Verifier"
    REGISTRY = "Demo-Registry"


# Default timeout for Verifier VP interaction (seconds)
DEFAULT_VP_TIMEOUT_SECONDS = 60

# Default timeout for HTTP requests via FlaskEndpoint (seconds)
DEFAULT_HTTP_TIMEOUT_SECONDS = 30
