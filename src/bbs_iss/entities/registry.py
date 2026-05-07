from typing import Dict, Optional
import bbs_iss.interfaces.requests_api as api

class RegistryInstance:
    def __init__(self):
        self._store: Dict[str, api.IssuerPublicData] = {}

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
