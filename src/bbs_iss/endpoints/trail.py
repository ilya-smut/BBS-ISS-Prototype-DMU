from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import bbs_iss.interfaces.requests_api as api


@dataclass
class TrailEntry:
    step: int
    timestamp: str
    sender: str
    receiver: str
    request_type: str
    detail: str  # Full output from message.get_print_string()


@dataclass
class RequestTrail:
    """Records the sequence of protocol messages in a single protocol execution."""
    protocol: str = ""
    entries: list[TrailEntry] = field(default_factory=list)
    status: str = "IN_PROGRESS"   # IN_PROGRESS | COMPLETED | FAILED
    error: Optional[str] = None
    completed_at: Optional[str] = None
    _step_counter: int = field(default=0, repr=False)

    def record(self, sender: str, receiver: str, message):
        self._step_counter += 1

        # Extract detail from get_print_string() if available
        if hasattr(message, 'get_print_string'):
            detail = message.get_print_string()
        else:
            detail = str(message)

        # Extract request type name
        if hasattr(message, 'request_type'):
            request_type = message.request_type.name
        else:
            request_type = type(message).__name__

        entry = TrailEntry(
            step=self._step_counter,
            timestamp=datetime.now(timezone.utc).isoformat(timespec='seconds'),
            sender=sender,
            receiver=receiver,
            request_type=request_type,
            detail=detail,
        )
        self.entries.append(entry)

    def mark_completed(self):
        self.status = "COMPLETED"
        self.completed_at = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

    def mark_failed(self, error_response: api.ErrorResponse):
        self.status = "FAILED"
        self.error = f"{error_response.error_type.name}: {error_response.message}"
        self.completed_at = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

    def mark_exception(self, exception: Exception):
        self.status = "FAILED"
        self.error = f"{type(exception).__name__}: {exception}"
        self.completed_at = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

    @property
    def last_response(self):
        if self.entries:
            return self.entries[-1]
        return None

    def print_trail(self, verbose: bool = False) -> str:
        lines = ["\n" + "=" * 60]
        lines.append(f"{'PROTOCOL TRAIL: ' + self.protocol:^60}")
        lines.append("=" * 60)
        lines.append(f"  Status: {self.status}")
        if self.completed_at:
            lines.append(f"  Completed: {self.completed_at}")
        if self.error:
            lines.append(f"  Error:  {self.error}")
        lines.append("-" * 60)

        for e in self.entries:
            lines.append(
                f"  [{e.step}] {e.sender} -> {e.receiver}  |  {e.request_type}"
            )
            if verbose:
                # Indent each line of the detail output
                for detail_line in e.detail.strip().split("\n"):
                    lines.append(f"      {detail_line}")
                lines.append("")

        lines.append("=" * 60 + "\n")
        return "\n".join(lines)
