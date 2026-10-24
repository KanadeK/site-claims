"""Read-only diagnostics for installed Python distribution file claims."""

__version__ = "0.1.0"

from .core import Limits, ScanError, scan

__all__ = ["Limits", "ScanError", "__version__", "scan"]
