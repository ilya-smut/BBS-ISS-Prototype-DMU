from typing import Dict
from bbs_iss.interfaces.requests_api import PublicKeyBLS, IssuerPublicData

class RegistryInstance:
    def __init__(self):
        self._store: Dict[str, IssuerPublicData] = {}

    def register_issuer(
        self, 
        name: str, 
        public_key: PublicKeyBLS, 
        epoch_size_days: int,
        reissue_window_days: int,
        initial_bitstring: str = "00"
    ) -> None:
        if name in self._store:
            raise ValueError(f"Issuer '{name}' is already registered.")
            
        self._store[name] = IssuerPublicData(
            public_key=public_key,
            revocation_bitstring=initial_bitstring,
            epoch_size_days=epoch_size_days,
            validity_window_days=reissue_window_days
        )

    def get_issuer_data(self, name: str) -> IssuerPublicData:
        if name not in self._store:
            raise KeyError(f"Issuer '{name}' not found in registry.")
        return self._store[name]

    def update_revocation_bitstring(self, name: str, new_bitstring: str) -> None:
        if name not in self._store:
            raise KeyError(f"Issuer '{name}' not found in registry.")
        self._store[name].revocation_bitstring = new_bitstring

    def is_revoked(self, name: str, bit_index: int) -> bool:
        if name not in self._store:
            raise KeyError(f"Issuer '{name}' not found in registry.")
            
        hex_str = self._store[name].revocation_bitstring
        try:
            bitstring_int = int(hex_str, 16)
            # Assuming index 0 is the least significant bit (right-to-left)
            return bool((bitstring_int >> bit_index) & 1)
        except ValueError:
            raise ValueError(f"Invalid hex bitstring for issuer '{name}'")
