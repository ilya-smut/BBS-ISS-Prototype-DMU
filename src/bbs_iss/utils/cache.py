from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, Optional
from bbs_iss.interfaces.requests_api import IssuerPublicData, CacheEntry
from bbs_iss.exceptions.exceptions import IssuerNotFoundInCacheError

class PublicDataCache:
    """
    Manages a local cache of IssuerPublicData to minimize registry lookups.
    Entries are stamped with an 'obtained_at' UTC timestamp.
    """
    def __init__(self):
        self._cache: Dict[str, CacheEntry] = {}

    def update(self, issuer_name: str, data: IssuerPublicData):
        """
        Updates the cache with new issuer data and stamps it with the current UTC time.
        """
        self._cache[issuer_name] = CacheEntry(
            issuer_data=data,
            obtained_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        )

    def get(self, issuer_name: str) -> Optional[IssuerPublicData]:
        """
        Retrieves the cached issuer data if it exists.
        """
        entry = self._cache.get(issuer_name)
        return entry.issuer_data if entry else None

    def get_entry(self, issuer_name: str) -> Optional[CacheEntry]:
        """
        Retrieves the full cache entry including timestamp.
        """
        return self._cache.get(issuer_name)

    def check_bit_index(self, issuer: str, bit_index_hex: str) -> bool:
        """
        Looks up the issuer's public data in the cache and checks the revocation status
        for the given bit index (hex).
        
        Raises IssuerNotFoundInCacheError if the issuer is not present in the cache.
        """
        data = self.get(issuer)
        if data is None:
            raise IssuerNotFoundInCacheError(f"Issuer '{issuer}' not found in local cache")
        return data.check_revocation_status(bit_index_hex)

    def clear(self):
        """
        Clears the local cache.
        """
        self._cache.clear()

    def get_cache_info(self) -> str:
        """
        Returns a nicely formatted summary of the current cache contents as a string.
        """
        if not self._cache:
            return "\n[Public Data Cache] Cache is currently empty."

        lines = ["\n" + "="*50]
        lines.append(f"{'PUBLIC DATA CACHE CONTENTS':^50}")
        lines.append("="*50)
        for issuer_name, entry in self._cache.items():
            data = entry.issuer_data
            pk_hex = data.public_key.key.hex()
            pk_short = f"{pk_hex[:10]}...{pk_hex[-10:]}"
            
            lines.append(f"Issuer Name:    {issuer_name}")
            lines.append(f"Obtained At:    {entry.obtained_at}")
            lines.append(f"Public Key:     {pk_short}")
            lines.append(f"Revocation:     {len(data.revocation_bitstring) * 4} bits")
            lines.append(f"Epoch Size:     {data.validity_window_days} days")
            lines.append(f"Valid For:      {data.valid_until_weeks} weeks")
            lines.append("-" * 50)
        lines.append(f"{'END OF CACHE':^50}")
        lines.append("="*50 + "\n")
        
        return "\n".join(lines)
