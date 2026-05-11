from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import bbs_iss.interfaces.requests_api as api


@dataclass
class TrailEntry:
    """A single recorded step in a protocol execution trail."""
    step: int
    timestamp: str
    sender: str
    receiver: str
    request_type: str
    detail: str  # Full output from message.get_print_string()


@dataclass
class RequestTrail:
    """
    Records the sequence of protocol messages exchanged during
    a single protocol execution (issuance, presentation, re-issuance, etc.).

    Provides both compact and verbose output modes for inspection.
    """
    protocol: str = ""
    entries: list[TrailEntry] = field(default_factory=list)
    status: str = "IN_PROGRESS"   # IN_PROGRESS | COMPLETED | FAILED
    error: Optional[str] = None
    _step_counter: int = field(default=0, repr=False)

    def record(self, sender: str, receiver: str, message):
        """
        Record a protocol message exchange.

        Parameters
        ----------
        sender : str
            Name of the sending entity (e.g. "Holder", "Issuer").
        receiver : str
            Name of the receiving entity.
        message : api.Request or subclass
            The protocol message being recorded. Its get_print_string()
            method is called for detailed output.
        """
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
        """Mark the protocol execution as successfully completed."""
        self.status = "COMPLETED"

    def mark_failed(self, error_response: api.ErrorResponse):
        """
        Mark the protocol execution as failed due to an ErrorResponse.

        Parameters
        ----------
        error_response : ErrorResponse
            The error that caused the failure.
        """
        self.status = "FAILED"
        self.error = f"{error_response.error_type.name}: {error_response.message}"

    def mark_exception(self, exception: Exception):
        """
        Mark the protocol execution as failed due to a Python exception.

        Parameters
        ----------
        exception : Exception
            The exception raised during protocol execution.
        """
        self.status = "FAILED"
        self.error = f"{type(exception).__name__}: {exception}"

    @property
    def last_response(self):
        """Return the message detail from the last recorded entry, or None."""
        if self.entries:
            return self.entries[-1]
        return None

    def print_trail(self, verbose: bool = False) -> str:
        """
        Render the trail as a formatted string.

        Parameters
        ----------
        verbose : bool
            If True, includes the full get_print_string() output for
            each step. If False, shows a compact one-line-per-step summary.

        Returns
        -------
        str
            Formatted trail output.
        """
        lines = ["\n" + "=" * 60]
        lines.append(f"{'PROTOCOL TRAIL: ' + self.protocol:^60}")
        lines.append("=" * 60)
        lines.append(f"  Status: {self.status}")
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
