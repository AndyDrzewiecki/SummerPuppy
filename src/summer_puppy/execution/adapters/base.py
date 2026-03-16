from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from summer_puppy.audit.logger import AuditLogger


class BaseAdapter:
    def __init__(self, audit_logger: AuditLogger) -> None:
        self._audit_logger = audit_logger
