"""Check registry and built-in non-destructive checks.

Importing this package registers all built-in checks. Third-party checks can be
added by subclassing :class:`wp_sentinel.checks.base.Check` and calling
:func:`register`.
"""

from .base import Check, CheckContext, register, all_checks

# Import built-in checks for their registration side effects.
from . import wp_version  # noqa: F401
from . import security_headers  # noqa: F401
from . import xmlrpc  # noqa: F401
from . import user_enum  # noqa: F401
from . import sensitive_files  # noqa: F401
from . import directory_listing  # noqa: F401
from . import tls  # noqa: F401
from . import plugins  # noqa: F401
from . import misc_endpoints  # noqa: F401

__all__ = ["Check", "CheckContext", "register", "all_checks"]
