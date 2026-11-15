"""
Simple synchronous pub/sub event bus.

Used to decouple the OPAV loop from CLI output, SIEM alerts, and ticket systems.
All handlers are called synchronously in the order they were registered.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Callable


class EventBus:
    """
    Synchronous publish-subscribe event bus.

    Usage:
        bus = EventBus()
        bus.subscribe("kill_switch", my_handler)
        bus.emit("kill_switch", reason="user request")

    Standard events emitted by OPAVLoop:
        kill_switch           — engagement killed
        hitl_gate_required    — human approval needed (reason=str)
        zero_subtasks         — AI returned empty queue
        finding_confirmed     — new CONFIRMED finding (finding_id=str)
        finding_unconfirmed   — new UNCONFIRMED finding
        scan_timeout          — discovery scan exceeded time limit
        circuit_breaker_trip  — circuit breaker tripped
    """

    def __init__(self):
        self._handlers: dict[str, list[Callable]] = defaultdict(list)

    def subscribe(self, event: str, handler: Callable) -> None:
        """Register a handler for the given event name."""
        self._handlers[event].append(handler)

    def unsubscribe(self, event: str, handler: Callable) -> None:
        """Remove a previously registered handler."""
        handlers = self._handlers.get(event, [])
        if handler in handlers:
            handlers.remove(handler)

    def emit(self, event: str, **kwargs) -> None:
        """
        Emit an event to all registered handlers.
        Handler exceptions are caught and logged to stderr to prevent
        one bad handler from breaking the OPAV loop.
        """
        for handler in list(self._handlers.get(event, [])):
            try:
                handler(**kwargs)
            except Exception as exc:
                import sys
                print(
                    f"[EventBus] Handler {handler.__name__!r} raised on "
                    f"event '{event}': {exc}",
                    file=sys.stderr,
                )

    def clear(self, event: str | None = None) -> None:
        """Remove all handlers (optionally for a specific event)."""
        if event:
            self._handlers.pop(event, None)
        else:
            self._handlers.clear()

    def event_names(self) -> list[str]:
        """Return all event names that have at least one handler."""
        return [e for e, h in self._handlers.items() if h]
