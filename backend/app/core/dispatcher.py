"""In-Process Asynchronous Event Dispatcher (ADR 0001).

Coordinates asynchronous event routing across modules within a single worker process.
Guarantees task retention against garbage collection, exception logging, and provides
a deterministic `drain()` hook for reliable automated testing.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from contracts.python.models import EventContract

logger = logging.getLogger("sentinelx.dispatcher")

EventHandler = Callable[[EventContract], Coroutine[Any, Any, None]]


class EventDispatcher:
    """In-process asynchronous publish-subscribe dispatcher."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Subscribes an asynchronous handler to an event type or '*' for all events."""
        self._subscribers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Unsubscribes an asynchronous handler."""
        if event_type in self._subscribers and handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)

    def dispatch(self, event: EventContract) -> list[asyncio.Task[None]]:
        """Dispatches an event asynchronously to all matching subscribers.

        Returns the created asyncio Tasks and holds strong references to them
        in self._tasks to prevent premature garbage collection.
        """
        handlers = list(self._subscribers.get(event.event_type, [])) + list(
            self._subscribers.get("*", [])
        )
        created_tasks: list[asyncio.Task[None]] = []

        for handler in handlers:
            task = asyncio.create_task(self._safe_execute(handler, event))
            self._tasks.add(task)
            task.add_done_callback(self._on_task_completed)
            created_tasks.append(task)

        return created_tasks

    async def _safe_execute(self, handler: EventHandler, event: EventContract) -> None:
        """Executes a subscriber handler safely, trapping and logging any unhandled exceptions."""
        try:
            await handler(event)
        except Exception:
            logger.exception(
                "Unhandled exception in subscriber %s handling event %s (%s)",
                handler.__name__,
                event.event_id,
                event.event_type,
            )

    def _on_task_completed(self, task: asyncio.Task[None]) -> None:
        """Callback to release the strong task reference upon completion."""
        self._tasks.discard(task)
        if not task.cancelled() and task.exception():
            logger.error("Event dispatcher task failed: %s", task.exception())

    async def drain(self, timeout: float = 10.0) -> None:
        """Awaits all currently executing subscriber tasks to complete.

        Essential hook for deterministic test suites and evaluation scripts.
        """
        loop = asyncio.get_running_loop()
        end_time = loop.time() + timeout

        while self._tasks:
            remaining = end_time - loop.time()
            if remaining <= 0:
                logger.warning(
                    "EventDispatcher drain() timed out with %d tasks remaining", len(self._tasks)
                )
                break
            current_tasks = list(self._tasks)
            await asyncio.wait(current_tasks, timeout=min(remaining, 0.5))

    def clear(self) -> None:
        """Clears all registered subscribers and cancels pending tasks (used in tests)."""
        self._subscribers.clear()
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()


# Global in-process dispatcher singleton
dispatcher = EventDispatcher()
