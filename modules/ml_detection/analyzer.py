"""Machine Learning Anomaly Detection & UEBA Capability Module (X6).

Provides pure-Python unsupervised outlier detection, rolling Z-score volume
analysis, dynamic Shannon entropy calculation, and Isolation Forest scoring
without heavy external dependencies (Law 1, Law 2, Law 6).
"""

from __future__ import annotations

import math
import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from contracts.python.models import FindingContract, SeverityLevel


def calculate_shannon_entropy(items: list[str]) -> float:
    """Calculates Shannon entropy in bits for a sequence of tokens or categorical values."""
    if not items:
        return 0.0
    total = len(items)
    counts: dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class RollingZScoreTracker:
    """Online Welford-style variance and mean tracker for rolling anomaly scoring."""

    def __init__(self, threshold_z: float = 3.0, min_stdev: float = 1.0) -> None:
        self.threshold_z = threshold_z
        self.min_stdev = min_stdev
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, x: float) -> tuple[float, bool]:
        """Updates online mean and variance, returning (z_score, is_anomaly)."""
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self._m2 += delta * delta2

        if self.count < 3:
            return 0.0, False

        variance = self._m2 / (self.count - 1)
        stdev = max(math.sqrt(variance), self.min_stdev)
        z_score = (x - self.mean) / stdev
        is_anomaly = abs(z_score) >= self.threshold_z
        return round(z_score, 3), is_anomaly


@dataclass
class IsolationTreeNode:
    """Node in an Isolation Tree."""

    split_feature: int | None = None
    split_value: float | None = None
    min_val: float | None = None
    max_val: float | None = None
    left: IsolationTreeNode | None = None
    right: IsolationTreeNode | None = None
    size: int = 0
    is_leaf: bool = False


class IsolationTree:
    """Pure-Python Isolation Tree for partitioning multi-dimensional continuous feature vectors."""

    def __init__(self, max_height: int, seed: int | None = None) -> None:
        self.max_height = max_height
        self.root: IsolationTreeNode | None = None
        self._rng = random.Random(seed)

    def fit(self, data: list[list[float]], current_height: int = 0) -> IsolationTreeNode:
        n_samples = len(data)
        if current_height >= self.max_height or n_samples <= 1:
            node = IsolationTreeNode(size=n_samples, is_leaf=True)
            if current_height == 0:
                self.root = node
            return node

        n_features = len(data[0])
        feature_idx = self._rng.randint(0, n_features - 1)
        vals = [row[feature_idx] for row in data]
        min_val, max_val = min(vals), max(vals)

        if math.isclose(min_val, max_val):
            node = IsolationTreeNode(size=n_samples, is_leaf=True, min_val=min_val, max_val=max_val)
            if current_height == 0:
                self.root = node
            return node

        split_value = self._rng.uniform(min_val, max_val)
        left_data = [row for row in data if row[feature_idx] < split_value]
        right_data = [row for row in data if row[feature_idx] >= split_value]

        left_node = self.fit(left_data, current_height + 1)
        right_node = self.fit(right_data, current_height + 1)

        node = IsolationTreeNode(
            split_feature=feature_idx,
            split_value=split_value,
            min_val=min_val,
            max_val=max_val,
            left=left_node,
            right=right_node,
            size=n_samples,
            is_leaf=False,
        )
        if current_height == 0:
            self.root = node
        return node

    def path_length(self, x: list[float], node: IsolationTreeNode | None = None, current_depth: int = 0) -> float:
        if node is None:
            node = self.root
        if node is None or node.is_leaf:
            if node is not None and node.size > 1:
                return current_depth + _c(node.size)
            return float(current_depth)

        if node.split_feature is not None and node.split_value is not None:
            feat_val = x[node.split_feature]
            # Check if point falls outside feature bounds observed during training
            if node.min_val is not None and node.max_val is not None:
                span = node.max_val - node.min_val
                if span > 1e-6:
                    if feat_val < node.min_val:
                        dist = node.min_val - feat_val
                        p_isolate = dist / (span + dist)
                        # Probability of separating this outlier immediately vs recurring
                        if p_isolate >= 0.5:
                            return float(current_depth + 1)
                    elif feat_val > node.max_val:
                        dist = feat_val - node.max_val
                        p_isolate = dist / (span + dist)
                        if p_isolate >= 0.5:
                            return float(current_depth + 1)

            if feat_val < node.split_value:
                return self.path_length(x, node.left, current_depth + 1)
            else:
                return self.path_length(x, node.right, current_depth + 1)
        return float(current_depth)


def _c(n: int) -> float:
    """Average path length of unsuccessful searches in a Binary Search Tree (BST)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    # Euler-Mascheroni constant ~ 0.5772156649
    return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class PureIsolationForest:
    """Pure-Python Isolation Forest ensemble for multidimensional anomaly scoring."""

    def __init__(self, n_trees: int = 25, sub_sample_size: int = 64, seed: int = 42) -> None:
        self.n_trees = n_trees
        self.sub_sample_size = sub_sample_size
        self.seed = seed
        self.trees: list[IsolationTree] = []
        self._rng = random.Random(seed)

    def fit(self, x: list[list[float]]) -> None:
        """Trains the isolation forest ensemble on reference baseline data."""
        self.trees = []
        n_samples = len(x)
        if n_samples == 0:
            return

        sample_size = min(self.sub_sample_size, n_samples)
        max_height = math.ceil(math.log2(max(sample_size, 2)))

        for i in range(self.n_trees):
            subsample = self._rng.sample(x, sample_size)
            tree = IsolationTree(max_height=max_height, seed=self.seed + i)
            tree.fit(subsample)
            self.trees.append(tree)

    def score(self, sample: list[float]) -> float:
        """Computes anomaly score between 0.0 and 1.0. Values > 0.60 indicate strong anomalies."""
        if not self.trees:
            return 0.0

        lengths = [tree.path_length(sample) for tree in self.trees]
        avg_length = sum(lengths) / len(lengths)
        c_factor = _c(self.sub_sample_size)
        if c_factor <= 0:
            return 0.0

        # Anomaly score s(x, n) = 2^(- E(h(x)) / c(n))
        score = math.pow(2.0, -(avg_length / c_factor))
        return round(score, 4)


@dataclass
class UEBAEntityProfile:
    """Entity profile tracking access hours, connection frequency, and entropy baselines."""

    entity_id: str
    access_hours: set[int] = field(default_factory=set)
    volume_tracker: RollingZScoreTracker = field(default_factory=lambda: RollingZScoreTracker(threshold_z=3.0))
    distinct_destinations: set[str] = field(default_factory=set)


class MLAnomalyDetector:
    """Main detector coordinating UEBA profiling, Z-score bounds, and Isolation Forest scoring."""

    def __init__(self, seed: int = 42) -> None:
        self.entity_profiles: dict[str, UEBAEntityProfile] = {}
        self.isolation_forest = PureIsolationForest(n_trees=30, sub_sample_size=64, seed=seed)
        self._is_trained = False
        self._seed = seed

    def train_baseline(self, baseline_features: list[list[float]]) -> None:
        """Trains the internal Isolation Forest on a baseline dataset."""
        if len(baseline_features) >= 10:
            self.isolation_forest.fit(baseline_features)
            self._is_trained = True

    def evaluate_telemetry(
        self,
        event: dict[str, Any],
        features: list[float] | None = None,
    ) -> FindingContract | None:
        """Evaluates an event dictionary and generates a FindingContract if an anomaly is detected."""
        source_ip = event.get("source_ip", "0.0.0.0")
        target_host = event.get("target_host") or event.get("destination_ip") or "unknown_host"
        asset_id = event.get("asset_id") or "unbound_asset"
        raw_time = event.get("event_time")
        if isinstance(raw_time, str):
            try:
                dt = datetime.fromisoformat(raw_time)
            except Exception:
                dt = datetime.now(UTC)
        elif isinstance(raw_time, datetime):
            dt = raw_time
        else:
            dt = datetime.now(UTC)

        # 1. Update UEBA Entity Profile
        if source_ip not in self.entity_profiles:
            profile = UEBAEntityProfile(entity_id=source_ip)
            # Default normal operating hours (e.g. 08:00 - 18:00) for demo baseline
            profile.access_hours.update(range(8, 19))
            self.entity_profiles[source_ip] = profile
        else:
            profile = self.entity_profiles[source_ip]

        anomalies_detected: list[str] = []
        evidence_data: dict[str, Any] = {
            "source_ip": source_ip,
            "target_host": target_host,
            "asset_id": asset_id,
            "evaluated_at": dt.isoformat(),
        }

        # 2. Check UEBA Off-Hours Access
        hour = dt.hour
        is_off_hours = hour not in profile.access_hours
        if is_off_hours and len(profile.access_hours) > 0:
            anomalies_detected.append(f"Off-hours access detected at {hour:02d}:00 UTC")
            evidence_data["off_hours_access"] = True
            evidence_data["access_hour"] = hour

        # 3. Check Volume Z-Score
        volume = float(event.get("details", {}).get("bytes_transferred", 1.0))
        z_score, is_volume_anomaly = profile.volume_tracker.update(volume)
        evidence_data["volume_z_score"] = z_score
        if is_volume_anomaly:
            anomalies_detected.append(f"Statistically anomalous data volume (Z-Score: {z_score})")
            evidence_data["volume_anomaly"] = True

        # 4. Check Isolation Forest Multi-Feature Vector
        if features and self._is_trained:
            if_score = self.isolation_forest.score(features)
            evidence_data["isolation_forest_score"] = if_score
            if if_score >= 0.62:
                anomalies_detected.append(f"High multidimensional isolation outlier score ({if_score})")
                evidence_data["isolation_outlier"] = True

        # 5. Shannon Entropy on Destination Sequences / Query tokens
        destination = event.get("destination_ip") or event.get("target_host")
        if destination:
            profile.distinct_destinations.add(str(destination))

        # Check detail tokens (e.g. queries, filenames, URIs)
        raw_payload = str(event.get("raw_payload", ""))
        entropy = calculate_shannon_entropy(raw_payload.split())
        evidence_data["payload_entropy"] = entropy
        if entropy > 4.5:
            anomalies_detected.append(f"Abnormal token entropy ({entropy} bits)")
            evidence_data["high_entropy"] = True

        if not anomalies_detected:
            return None

        # Determine severity based on anomaly count and metrics
        severity: SeverityLevel
        if len(anomalies_detected) >= 2 or evidence_data.get("volume_z_score", 0) > 4.0:
            severity = "critical"
        elif len(anomalies_detected) == 1:
            severity = "high"
        else:
            severity = "medium"

        return FindingContract(
            finding_id=uuid.uuid4(),
            tool_name="ml_anomaly_detector",
            rule_id="RULE-ML-ANOMALY",
            severity=severity,
            target=f"{source_ip} -> {target_host}",
            description="; ".join(anomalies_detected),
            evidence=evidence_data,
            timestamp=datetime.now(UTC),
            mitre_attack_id="T1078",
        )
