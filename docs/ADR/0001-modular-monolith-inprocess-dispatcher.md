# ADR 0001: Modular Monolith and In-Process Event Dispatcher

## Status
Accepted

## Context
When architecting SentinelX's security event pipeline ($\text{Ingest} \to \text{Detect} \to \text{Alert} \to \text{Incident}$), we evaluated two primary architectural topologies:
1. **Distributed Microservices with Message Broker (Kafka / RabbitMQ / Redis Streams)**: Multiple decoupled services communicating over network message queues.
2. **Modular Monolith with In-Process Event Dispatcher**: A single deployable FastAPI application with strict internal package boundaries and an asynchronous in-memory event dispatcher.

For Phase 1 (Minor Project), introducing distributed brokers creates significant operational overhead:
* Requires managing multiple containers, network partitions, deserialization overhead, and message deduplication.
* Complicates local evaluation, automated unit testing, and academic benchmarking.
* Introduces distributed consensus challenges for sequential cryptographic hash-chained audit logging.

## Decision
We adopt a **Modular Monolith** architecture with an **In-Process Asynchronous Event Dispatcher** (`backend/app/core/dispatcher.py`) running in a single worker process (`--workers 1`):
1. **Strict Module Boundaries**: The Shared Core Platform (M1-M7) is organized into isolated domain packages (`services/`, `models/`, `schemas/`).
2. **Post-Commit Dispatch**: After an incoming event is committed to the database, the dispatcher invokes subscribers via `asyncio.create_task()`.
3. **Strong Task References & Exception Handling**: Active subscriber tasks are retained in a task set with exception-logging callbacks, preventing garbage collection.
4. **Deterministic Testing**: The dispatcher exposes an `await dispatcher.drain()` hook, allowing test suites to deterministically await pending subscriber execution.
5. **Single-Worker Invariant**: The Minor project backend is explicitly configured with `--workers 1` in both Docker and Uvicorn. This ensures process-level `asyncio.Lock()` mutexes effectively serialize audit log sequence numbers and hash chains.

## Consequences
* **Positive**: Fast local execution, zero-configuration developer onboarding, deterministic test assertions, simple deployment via Docker Compose, and mathematically guaranteed audit sequence ordering.
* **Negative**: Scaling beyond a single node is deferred. Migrating to external distributed brokers (Kafka/RabbitMQ) is reserved for Phase 8 (Enterprise Scale).
