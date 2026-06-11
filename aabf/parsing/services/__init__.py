"""Per-service parsers.

Each module implements one service's parser: it knows which store keys / JSON
fields / table columns map to which agent-artifact category, and emits
:class:`~aabf.parsing.records.AgentRecord` objects. Shared storage reading is
delegated to :mod:`aabf.utils` so these modules only hold service-specific
knowledge.
"""

from .base import BaseServiceParser

__all__ = ["BaseServiceParser"]
