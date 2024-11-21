"""Monitor package for different types of monitoring."""

from .base import BaseMonitor, Check
from .http import HTTPMonitor

# Map monitor types to their respective classes
MONITOR_TYPES = {
    'http': HTTPMonitor,
}

# Optionally add DNS monitoring if aiodns is available
try:
    from .dns import DNSMonitor
    MONITOR_TYPES['dns'] = DNSMonitor
    __all__ = ['BaseMonitor', 'Check', 'HTTPMonitor', 'DNSMonitor', 'MONITOR_TYPES']
except ImportError:
    __all__ = ['BaseMonitor', 'Check', 'HTTPMonitor', 'MONITOR_TYPES']
