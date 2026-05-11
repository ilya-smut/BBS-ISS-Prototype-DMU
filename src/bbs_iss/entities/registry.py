from typing import Dict, Optional
import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.entity import Entity

class RegistryInstance(Entity):
    def __init__(self):
        self._store: Dict[str, api.IssuerPublicData] = {}

    @property
    def available(self) -> bool:
        """Registry is always available — it has no interaction state."""
        return True

    def reset(self):
        """No-op — Registry has no pending interaction state to clear."""
        pass

    def process_request(self, request: api.Request) -> api.IssuerDetailsResponse:
        if request.request_type == api.RequestType.REGISTER_ISSUER_DETAILS:
            return self._handle_registration(request)
        elif request.request_type == api.RequestType.UPDATE_ISSUER_DETAILS:
            return self._handle_update(request)
        elif request.request_type == api.RequestType.GET_ISSUER_DETAILS:
            return self._handle_get(request)
        elif request.request_type == api.RequestType.BULK_ISSUER_DETAILS_REQUEST:
            return self._handle_bulk_get(request)
        else:
            raise ValueError(f"Registry cannot process request type: {request.request_type}")

    def _handle_registration(self, request: api.RegisterIssuerDetailsRequest) -> api.IssuerDetailsResponse:
        name = request.issuer_name
        if name in self._store:
            # Registration fails (name taken), return existing data
            return api.IssuerDetailsResponse(issuer_data=self._store[name])
        
        # Registration succeeds, save and return new data
        self._store[name] = request.issuer_data
        return api.IssuerDetailsResponse(issuer_data=request.issuer_data)

    def _handle_update(self, request: api.UpdateIssuerDetailsRequest) -> api.IssuerDetailsResponse:
        name = request.issuer_name
        if name not in self._store:
            # Update fails (issuer not found), return None
            return api.IssuerDetailsResponse(issuer_data=None)
            
        # Update succeeds, overwrite and return new data
        self._store[name] = request.issuer_data
        return api.IssuerDetailsResponse(issuer_data=request.issuer_data)

    def _handle_get(self, request: api.GetIssuerDetailsRequest) -> api.IssuerDetailsResponse:
        name = request.issuer_name
        if name not in self._store:
            # Query fails (issuer not found), return None
            return api.IssuerDetailsResponse(issuer_data=None)
            
        # Query succeeds, return existing data
        return api.IssuerDetailsResponse(issuer_data=self._store[name])

    def _handle_bulk_get(self, request: api.BulkGetIssuerDetailsRequest) -> api.BulkIssuerDetailsResponse:
        return api.BulkIssuerDetailsResponse(issuers_data=list(self._store.values()))

    def get_status_string(self) -> str:
        """
        Returns a nicely formatted summary of all data stored in the registry.
        """
        if not self._store:
            return "\n[Registry] Registry is currently empty."

        lines = ["\n" + "="*50]
        lines.append(f"{'REGISTRY CONTENTS':^50}")
        lines.append("="*50)
        for name, data in self._store.items():
            pk_hex = data.public_key.key.hex()
            pk_short = f"{pk_hex[:10]}...{pk_hex[-10:]}"
            
            lines.append(f"Issuer Name:    {name}")
            lines.append(f"Public Key:     {pk_short}")
            lines.append(f"Revocation:     {len(data.revocation_bitstring) * 4} bits")
            lines.append(f"Epoch Size:     {data.validity_window_days} days")
            lines.append(f"Valid For:      {data.valid_until_weeks} weeks")
            lines.append("-" * 50)
        lines.append(f"{'END OF REGISTRY':^50}")
        lines.append("="*50 + "\n")
        
        return "\n".join(lines)
