"""
Factory for creating BloodHound clients
"""

from .base import BloodHoundClient
from .legacy import BloodHoundLegacyClient
from .ce import BloodHoundCEClient


def create_bloodhound_client(edition: str, **kwargs) -> BloodHoundClient:
    """
    Factory function to create the appropriate BloodHound client

    Args:
        edition: 'legacy' or 'ce'
        **kwargs: Client-specific parameters

    Returns:
        BloodHoundClient instance
    """
    normalized = edition.lower()
    if normalized == "legacy":
        return BloodHoundLegacyClient(**kwargs)
    if normalized == "ce":
        return BloodHoundCEClient(**kwargs)
    raise ValueError(f"Unsupported edition: {edition}. Use 'legacy' or 'ce'")
