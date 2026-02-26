"""
Base classes for BloodHound CLI operations
"""

# pylint: disable=too-many-arguments,too-many-positional-arguments
from abc import ABC, abstractmethod
from typing import List, Dict, Optional


class BloodHoundClient(ABC):
    """Abstract base class for BloodHound clients"""

    def __init__(self, debug: bool = False, verbose: bool = False):
        self.debug = debug
        self.verbose = verbose

    @abstractmethod
    def get_users(self, domain: str) -> List[str]:
        """Get users from a specific domain"""
        raise NotImplementedError

    @abstractmethod
    def get_computers(self, domain: str, laps: Optional[bool] = None) -> List[str]:
        """Get computers from a specific domain"""
        raise NotImplementedError

    @abstractmethod
    def get_admin_users(self, domain: str) -> List[str]:
        """Get admin users from a specific domain"""
        raise NotImplementedError

    @abstractmethod
    def get_highvalue_users(self, domain: str) -> List[str]:
        """Get high value users from a specific domain"""
        raise NotImplementedError

    @abstractmethod
    def get_password_not_required_users(self, domain: str) -> List[str]:
        """Get users that don't require passwords"""
        raise NotImplementedError

    @abstractmethod
    def get_password_never_expires_users(self, domain: str) -> List[str]:
        """Get users with passwords that never expire"""
        raise NotImplementedError

    @abstractmethod
    def get_user_groups(
        self, domain: str, username: str, recursive: bool = True
    ) -> List[str]:
        """Get groups for a specific user"""
        raise NotImplementedError

    @abstractmethod
    def get_sessions(self, domain: str, da: bool = False) -> List[Dict]:
        """Get user sessions"""
        raise NotImplementedError

    @abstractmethod
    def get_password_last_change(
        self, domain: str, user: Optional[str] = None
    ) -> List[Dict]:
        """Get password last change information"""
        raise NotImplementedError

    @abstractmethod
    def get_critical_aces(
        self,
        source_domain: str,
        high_value: bool = False,
        username: str = "all",
        target_domain: str = "all",
        relation: str = "all",
    ) -> List[Dict]:
        """Get critical ACEs"""
        raise NotImplementedError

    @abstractmethod
    def get_access_paths(
        self, source: str, connection: str, target: str, domain: str
    ) -> List[Dict]:
        """Get access paths"""
        raise NotImplementedError

    @abstractmethod
    def get_critical_aces_by_domain(
        self,
        domain: str,
        blacklist: List[str],
        high_value: bool = False,
    ) -> List[Dict]:
        """Get critical ACEs by domain"""
        raise NotImplementedError

    def close(self):
        """Close the client connection"""
        raise NotImplementedError
