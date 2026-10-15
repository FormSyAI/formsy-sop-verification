"""Cooperative cancellation; retained artifacts never become a successful audit."""

from .failure_reporting import safe_stage


class AuditCancelled(Exception):
    def __init__(self, stage=""):
        super().__init__("audit_cancelled")
        self.stage = safe_stage(stage)
        self.recording_error = None


def check_cancelled(event, stage=""):
    if event is not None and event.is_set():
        raise AuditCancelled(stage)
