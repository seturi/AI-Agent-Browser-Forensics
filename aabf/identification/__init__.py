"""Identification & classification module (paper Section 5.2).

Identifies which AI agent browser was used from local traces and classifies its
service type (local-centric / cloud-centric / hybrid). Public entry points are
re-exported here so callers can ``from aabf.identification import identify``.
"""

from .identify import DEFAULT_MIN_CONFIDENCE, identify

__all__ = ["identify", "DEFAULT_MIN_CONFIDENCE"]
