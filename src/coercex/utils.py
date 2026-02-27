"""Backward-compatible re-exports from split modules.

This module previously contained all utility types, helpers, and error
classification in a single file.  The code has been split into focused
modules:

- :mod:`coercex.models`  -- Credentials, ScanResult, ScanStats, Transport, TriggerResult
- :mod:`coercex.errors`  -- classify_error(), error code sets
- :mod:`coercex.unc`     -- build_unc_path()
- :mod:`coercex.net`     -- get_local_ip(), random_string()

All names are re-exported here so existing ``from coercex.utils import ...``
statements continue to work.
"""

from __future__ import annotations

# Re-export everything from the new modules
from coercex.errors import (
    ACCESSIBLE_ERROR_CODES as ACCESSIBLE_ERROR_CODES,
    ACCESS_DENIED_CODES as ACCESS_DENIED_CODES,
    NOT_AVAILABLE_CODES as NOT_AVAILABLE_CODES,
    classify_error as classify_error,
)
from coercex.models import (
    Credentials as Credentials,
    ScanResult as ScanResult,
    ScanStats as ScanStats,
    Transport as Transport,
    TriggerResult as TriggerResult,
)
from coercex.net import (
    get_local_ip as get_local_ip,
    random_string as random_string,
)
from coercex.unc import build_unc_path as build_unc_path
