"""SentinelX Detection Evaluation & Benchmarking Tool (Step 7).

Evaluates detection engine accuracy, false positive resilience, and latency
against a ground-truth labelled evaluation dataset.
Supports offline ASGI in-process testing (default) and live REST API evaluation.

Metrics Computed:
  * True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
  * Precision = TP / (TP + FP)
  * Recall = TP / (TP + FN)
  * F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
  * Specificity = TN / (TN + FP)
  * Mean Detection Latency (ms)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.app.core.config import settings
from backend.app.core.database import Base
from backend.app.core.dispatcher import dispatcher
from backend.app.main import app
from backend.app.models.alert import Alert
from backend.app.models.asset import Asset
from backend.app.services.detection_service import detection_service

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelx.evaluator")

DEFAULT_ASSETS = [
    {
        "id": "server-prod-01",
        "hostname": "server-prod-01",
        "ip_address": "192.168.1.10",
        "asset_type": "server",
        "criticality": "high",
        "description": "Primary Application Server",
    },
    {
        "id": "db-prod-01",
        "hostname": "db-prod-01",
        "ip_address": "192.168.1.20",
        "asset_type": "database",
        "criticality": "critical",
        "description": "Core Production Database",
    },
    {
        "id": "firewall-edge-01",
        "hostname": "firewall-edge-01",
        "ip_address": "192.168.1.1",
        "asset_type": "firewall",
        "criticality": "high",
        "description": "Perimeter Firewall",
    },
]


@dataclass
class CategoryMetrics:
    """Metrics tracking for an attack category or benign baseline."""

    name: str
    rule_id: str | None
    total_scenarios: int = 0
    total_events: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        if denom == 0:
            return 1.0 if self.true_negatives > 0 else 0.0
        return self.true_positives / denom

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        if denom == 0:
            return 1.0 if self.true_negatives > 0 else 0.0
        return self.true_positives / denom

    @property
    def f1_score(self) -> float | None:
        if (self.true_positives + self.false_positives + self.false_negatives) == 0:
            return None
        p, r = self.precision, self.recall
        if (p + r) == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def specificity(self) -> float:
        denom = self.true_negatives + self.false_positives
        if denom == 0:
            return 1.0
        return self.true_negatives / denom

    @property
    def mean_latency_ms(self) -> float:
        return (sum(self.latencies_ms) / len(self.latencies_ms)) if self.latencies_ms else 0.0


class EvaluationHarness:
    """Orchestrates test dataset ingestion and detection metrics calculation."""

    def __init__(self, dataset_path: Path, api_key: str = settings.INGEST_API_KEY) -> None:
        self.dataset_path = dataset_path
        self.api_key = api_key
        with open(dataset_path, encoding="utf-8") as f:
            self.data = json.load(f)
        self.scenarios = self.data.get("scenarios", [])

    async def run_offline_evaluation(self) -> dict[str, CategoryMetrics]:
        """Runs offline evaluation against in-process FastAPI app with isolated SQLite database."""
        tmp_dir = tempfile.mkdtemp(prefix="sentinelx_eval_")
        db_path = Path(tmp_dir) / "eval.db"
        db_url = f"sqlite+aiosqlite:///{db_path.as_posix()}"

        engine = create_async_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30},
        )

        @event.listens_for(Engine, "connect")
        def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        # Patch core database references
        import backend.app.core.database as core_db

        orig_engine = core_db.engine
        orig_session_factory = core_db.async_session_factory

        core_db.engine = engine
        core_db.async_session_factory = session_factory

        async def override_get_db():
            async with session_factory() as session:
                yield session

        app.dependency_overrides[core_db.get_db] = override_get_db

        try:
            # Create schema and seed CMDB assets
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            async with session_factory() as session:
                for asset_info in DEFAULT_ASSETS:
                    session.add(Asset(**asset_info))
                await session.commit()

            detection_service.load_rules()

            # Execute evaluation
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                results = await self._execute_scenarios(client, session_factory)
                return results

        finally:
            app.dependency_overrides.clear()
            core_db.engine = orig_engine
            core_db.async_session_factory = orig_session_factory
            await engine.dispose()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def run_live_evaluation(
        self,
        base_url: str,
        username: str = "admin",
        password: str = "Admin123!Secure",
    ) -> dict[str, CategoryMetrics]:
        """Runs evaluation against an active live REST API server."""
        async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=15.0) as client:
            auth_token = None
            try:
                login_res = await client.post(
                    "/api/v1/auth/login",
                    json={"username": username, "password": password},
                )
                if login_res.status_code == 200:
                    auth_token = login_res.json().get("access_token")
            except Exception:
                logger.warning("Could not obtain JWT token for live evaluation alert lookup")
            return await self._execute_scenarios(client, None, auth_token=auth_token)

    async def _execute_scenarios(
        self,
        client: httpx.AsyncClient,
        session_factory: Any | None,
        auth_token: str | None = None,
    ) -> dict[str, CategoryMetrics]:
        """Iterates through scenarios, feeds events, and measures outcomes."""
        categories: dict[str, CategoryMetrics] = {}
        headers = {"Content-Type": "application/json", "X-API-Key": self.api_key}
        alert_headers = (
            {"Authorization": f"Bearer {auth_token}"} if auth_token else headers
        )

        for scen in self.scenarios:
            cat_name = scen.get("category", "unknown")
            label = scen.get("label", "benign")
            expected_rule_id = scen.get("expected_rule_id")
            source_ip = scen.get("source_ip")
            events = scen.get("events", [])

            if cat_name not in categories:
                categories[cat_name] = CategoryMetrics(name=cat_name, rule_id=expected_rule_id)
            cat = categories[cat_name]
            cat.total_scenarios += 1
            cat.total_events += len(events)

            t_start = time.perf_counter()

            # Ingest all events for this scenario
            for ev in events:
                payload = {
                    "source_ip": ev["source_ip"],
                    "destination_ip": ev.get("destination_ip"),
                    "destination_port": ev.get("destination_port"),
                    "source_port": ev.get("source_port"),
                    "event_type": ev["event_type"],
                    "target_host": ev.get("target_host"),
                    "event_time": ev["event_time"],
                    "raw_payload": ev.get("raw_payload"),
                    "details": ev.get("details", {}),
                }
                resp = await client.post("/api/v1/events/ingest", json=payload, headers=headers)
                if resp.status_code != 201:
                    logger.error(
                        "Failed ingesting event %s: HTTP %d", ev.get("event_id"), resp.status_code
                    )

            # Drain in-process dispatcher queue to guarantee rule execution
            if session_factory:
                await dispatcher.drain(timeout=10.0)
            else:
                # Allow live remote server's async background workers to process
                await asyncio.sleep(0.3)

            t_end = time.perf_counter()
            wall_latency_ms = (t_end - t_start) * 1000.0

            # Query alerts generated for this scenario's source_ip
            matched_alerts: list[Any] = []
            if session_factory:
                async with session_factory() as session:
                    stmt = select(Alert).where(Alert.source_ip == source_ip)
                    res = await session.execute(stmt)
                    matched_alerts = list(res.scalars().all())
            else:
                for _ in range(6):
                    resp = await client.get(f"/api/v1/alerts?search={source_ip}&limit=100", headers=alert_headers)
                    if resp.status_code == 200:
                        body = resp.json()
                        all_alerts = body if isinstance(body, list) else body.get("items", [])
                        matched_alerts = [a for a in all_alerts if a.get("source_ip") == source_ip]
                        if matched_alerts or label == "benign":
                            break
                    await asyncio.sleep(0.3)

            # Evaluate outcome against ground truth label
            if label == "attack":
                # Must match expected_rule_id
                correct_alert = any(
                    (getattr(a, "rule_id", None) or a.get("rule_id")) == expected_rule_id
                    for a in matched_alerts
                )
                if correct_alert:
                    cat.true_positives += 1
                    cat.latencies_ms.append(wall_latency_ms)
                else:
                    cat.false_negatives += 1
            else:  # benign
                if not matched_alerts:
                    cat.true_negatives += 1
                else:
                    cat.false_positives += 1

        return categories


def format_evaluation_report(categories: dict[str, CategoryMetrics]) -> str:
    """Formats an academic evaluation benchmarking report table."""
    total_scenarios = sum(c.total_scenarios for c in categories.values())
    total_events = sum(c.total_events for c in categories.values())
    total_tp = sum(c.true_positives for c in categories.values())
    total_fp = sum(c.false_positives for c in categories.values())
    total_tn = sum(c.true_negatives for c in categories.values())
    total_fn = sum(c.false_negatives for c in categories.values())
    all_latencies = [lat for c in categories.values() for lat in c.latencies_ms]

    denom_p = total_tp + total_fp
    overall_precision = (total_tp / denom_p) if denom_p > 0 else 1.0
    denom_r = total_tp + total_fn
    overall_recall = (total_tp / denom_r) if denom_r > 0 else 1.0
    overall_f1 = (
        (2 * overall_precision * overall_recall / (overall_precision + overall_recall))
        if (overall_precision + overall_recall) > 0
        else 0.0
    )
    denom_spec = total_tn + total_fp
    overall_spec = (total_tn / denom_spec) if denom_spec > 0 else 1.0
    mean_latency = (sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0

    lines = []
    sep = "=" * 94
    lines.append("\n" + sep)
    lines.append(" SentinelX SOC Detection Engine: Academic Evaluation & Benchmark Report")
    lines.append(sep)
    lines.append(
        f"{'Category / Test Suite':<24} | {'Scen':>4} | {'Events':>6} | {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} | "
        f"{'Precision':>9} | {'Recall':>8} | {'F1-Score':>8} | {'Latency':>9}"
    )
    lines.append("-" * 94)

    for cat_name, c in categories.items():
        p_str = f"{c.precision * 100:.1f}%" if (c.true_positives + c.false_positives) > 0 else "N/A"
        r_str = f"{c.recall * 100:.1f}%" if (c.true_positives + c.false_negatives) > 0 else "N/A"
        f1_str = f"{c.f1_score:.3f}" if c.f1_score is not None else "N/A"
        lat_str = f"{c.mean_latency_ms:.1f} ms" if c.latencies_ms else "-"

        lines.append(
            f"{cat_name:<24} | {c.total_scenarios:>4} | {c.total_events:>6} | "
            f"{c.true_positives:>3} {c.false_positives:>3} {c.true_negatives:>3} {c.false_negatives:>3} | "
            f"{p_str:>9} | {r_str:>8} | {f1_str:>8} | {lat_str:>9}"
        )

    lines.append("-" * 94)
    lines.append(
        f"{'OVERALL TOTALS':<24} | {total_scenarios:>4} | {total_events:>6} | "
        f"{total_tp:>3} {total_fp:>3} {total_tn:>3} {total_fn:>3} | "
        f"{overall_precision * 100:>8.1f}% | {overall_recall * 100:>7.1f}% | {overall_f1:>8.3f} | {mean_latency:>6.1f} ms"
    )
    lines.append(sep)
    lines.append(
        f" Performance Summary: Precision={overall_precision*100:.1f}% | Recall={overall_recall*100:.1f}% | "
        f"F1={overall_f1:.3f} | Specificity={overall_spec*100:.1f}%"
    )
    lines.append(
        f" Benchmark Result   : {'PASSED [VERIFIED]' if (overall_precision >= 0.90 and overall_recall >= 0.90) else 'FAILED'}"
    )
    lines.append(sep + "\n")

    return "\n".join(lines)


def export_json_report(
    output_path: Path,
    categories: dict[str, CategoryMetrics],
) -> None:
    """Exports structured evaluation metrics to JSON file."""
    total_tp = sum(c.true_positives for c in categories.values())
    total_fp = sum(c.false_positives for c in categories.values())
    total_tn = sum(c.true_negatives for c in categories.values())
    total_fn = sum(c.false_negatives for c in categories.values())
    all_latencies = [lat for c in categories.values() for lat in c.latencies_ms]

    denom_p = total_tp + total_fp
    prec = (total_tp / denom_p) if denom_p > 0 else 1.0
    denom_r = total_tp + total_fn
    rec = (total_tp / denom_r) if denom_r > 0 else 1.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    report_dict = {
        "timestamp": datetime.now(UTC).isoformat(),
        "summary": {
            "total_scenarios": sum(c.total_scenarios for c in categories.values()),
            "total_events": sum(c.total_events for c in categories.values()),
            "true_positives": total_tp,
            "false_positives": total_fp,
            "true_negatives": total_tn,
            "false_negatives": total_fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "mean_latency_ms": round(
                (sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0, 2
            ),
        },
        "categories": {
            cat_name: {
                "rule_id": c.rule_id,
                "scenarios": c.total_scenarios,
                "events": c.total_events,
                "tp": c.true_positives,
                "fp": c.false_positives,
                "tn": c.true_negatives,
                "fn": c.false_negatives,
                "precision": round(c.precision, 4),
                "recall": round(c.recall, 4),
                "f1_score": round(c.f1_score, 4) if c.f1_score is not None else None,
                "mean_latency_ms": round(c.mean_latency_ms, 2),
            }
            for cat_name, c in categories.items()
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)


async def async_main(args: argparse.Namespace) -> int:
    dataset_path = Path(args.dataset).resolve()
    if not dataset_path.exists():
        print(f"[!] Error: Dataset file not found at {dataset_path}")
        return 1

    harness = EvaluationHarness(dataset_path=dataset_path, api_key=args.api_key)

    if args.live_url:
        print(f"[*] Running LIVE evaluation against {args.live_url}...")
        categories = await harness.run_live_evaluation(args.live_url)
    else:
        print("[*] Running OFFLINE in-process evaluation against FastAPI engine...")
        categories = await harness.run_offline_evaluation()

    report_text = format_evaluation_report(categories)
    print(report_text)

    if args.json_output:
        out_path = Path(args.json_output).resolve()
        export_json_report(out_path, categories)
        print(f"[*] JSON evaluation report written to {out_path}")

    # Compute overall F1 and check exit criteria
    total_tp = sum(c.true_positives for c in categories.values())
    total_fp = sum(c.false_positives for c in categories.values())
    total_fn = sum(c.false_negatives for c in categories.values())

    denom_p = total_tp + total_fp
    prec = (total_tp / denom_p) if denom_p > 0 else 1.0
    denom_r = total_tp + total_fn
    rec = (total_tp / denom_r) if denom_r > 0 else 1.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    if prec >= args.min_precision and rec >= args.min_recall and f1 >= args.min_f1:
        return 0
    else:
        print(
            f"[!] Evaluation failed exit threshold: Precision={prec:.3f} (min {args.min_precision}), "
            f"Recall={rec:.3f} (min {args.min_recall}), F1={f1:.3f} (min {args.min_f1})"
        )
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelX Detection Evaluation Tool")
    parser.add_argument(
        "--dataset",
        default="tests/fixtures/labelled_evaluation_dataset.json",
        help="Path to ground truth labelled JSON dataset",
    )
    parser.add_argument(
        "--live-url",
        default=None,
        help="Target live API base URL (if omitted, runs offline ASGI harness)",
    )
    parser.add_argument(
        "--api-key",
        default=settings.INGEST_API_KEY,
        help="Ingestion API key",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="Path to write JSON evaluation metrics report",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.90,
        help="Minimum required precision threshold (default: 0.90)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.90,
        help="Minimum required recall threshold (default: 0.90)",
    )
    parser.add_argument(
        "--min-f1",
        type=float,
        default=0.90,
        help="Minimum required F1 threshold (default: 0.90)",
    )

    args = parser.parse_args()
    code = asyncio.run(async_main(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
