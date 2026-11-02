"""Common interface for website discovery providers."""

from abc import ABC, abstractmethod


class DiscoveryProvider(ABC):
    """Base class for passive website discovery providers."""

    @abstractmethod
    def search(self, query, limit=10):
        """
        Return candidate websites from a discovery source.

        Results must contain publicly available discovery evidence.
        This method must not perform vulnerability testing.
        """
        raise NotImplementedError