"""Unit tests for the In-Process Event Dispatcher (ADR 0001).

Verifies asynchronous publish-subscribe mechanics, wildcard event handling,
exception safety, and the deterministic drain() synchronization hook.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest

from backend.app.core.dispatcher import EventDispatcher
from contracts.python.models import EventContract


def create_sample_event(event_type: str = "auth_failed") -> EventContract:
    return EventContract(
        event_id=uuid.uuid4(),
        source_ip="192.168.1.50",
        event_type=event_type,
        event_time=datetime.now(UTC),
        ingest_time=datetime.now(UTC),
        details={"user": "admin"},
    )


@pytest.mark.asyncio
async def test_subscribe_and_dispatch():
    dispatcher = EventDispatcher()
    received_events = []

    async def on_auth_failed(event: EventContract) -> None:
        received_events.append(event)

    dispatcher.subscribe("auth_failed", on_auth_failed)
    event = create_sample_event("auth_failed")

    tasks = dispatcher.dispatch(event)
    assert len(tasks) == 1

    await dispatcher.drain()
    assert len(received_events) == 1
    assert received_events[0].event_id == event.event_id


@pytest.mark.asyncio
async def test_wildcard_subscriber_receives_all_events():
    dispatcher = EventDispatcher()
    all_events = []

    async def wildcard_handler(event: EventContract) -> None:
        all_events.append(event)

    dispatcher.subscribe("*", wildcard_handler)

    dispatcher.dispatch(create_sample_event("auth_failed"))
    dispatcher.dispatch(create_sample_event("connection_attempt"))
    dispatcher.dispatch(create_sample_event("web_access"))

    await dispatcher.drain()
    assert len(all_events) == 3
    event_types = {e.event_type for e in all_events}
    assert event_types == {"auth_failed", "connection_attempt", "web_access"}


@pytest.mark.asyncio
async def test_multiple_subscribers_execute_concurrently():
    dispatcher = EventDispatcher()
    results = []

    async def handler_one(event: EventContract) -> None:
        await asyncio.sleep(0.01)
        results.append("one")

    async def handler_two(event: EventContract) -> None:
        await asyncio.sleep(0.01)
        results.append("two")

    dispatcher.subscribe("port_scan", handler_one)
    dispatcher.subscribe("port_scan", handler_two)

    dispatcher.dispatch(create_sample_event("port_scan"))
    await dispatcher.drain()

    assert set(results) == {"one", "two"}


@pytest.mark.asyncio
async def test_subscriber_exception_isolation():
    dispatcher = EventDispatcher()
    successful_runs = []

    async def failing_handler(event: EventContract) -> None:
        raise RuntimeError("Simulated subscriber crash")

    async def healthy_handler(event: EventContract) -> None:
        successful_runs.append(event.event_id)

    dispatcher.subscribe("auth_failed", failing_handler)
    dispatcher.subscribe("auth_failed", healthy_handler)

    event = create_sample_event("auth_failed")
    dispatcher.dispatch(event)

    # Must complete cleanly without propagating exception outward
    await dispatcher.drain()

    assert len(successful_runs) == 1
    assert successful_runs[0] == event.event_id


@pytest.mark.asyncio
async def test_unsubscribe_removes_handler():
    dispatcher = EventDispatcher()
    calls = []

    async def handler(event: EventContract) -> None:
        calls.append(event)

    dispatcher.subscribe("auth_failed", handler)
    dispatcher.unsubscribe("auth_failed", handler)

    dispatcher.dispatch(create_sample_event("auth_failed"))
    await dispatcher.drain()

    assert len(calls) == 0
