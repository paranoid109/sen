# Machine Learning Anomaly Detection & UEBA Capability Module (X6)

## 1. Overview
The **ML Anomaly Detection & UEBA Capability Module (X6)** provides lightweight, pure-Python unsupervised outlier scoring and statistical behavioral modeling to discover stealthy zero-day attacks, off-hours access, volume spikes, and high-entropy payloads that evade static signature rules.

## 2. Decoupled Architecture (Law 1 & Law 2)
* Strictly decoupled from `backend/app/` (Core M1–M7) — conforms to **Law 1**.
* Ingests JSON event records and emits structured findings conforming to `contracts/findings/finding_contract.json` (**Law 2**).
* Can run in offline batch mode or stream findings directly to the SentinelX Ingest API (`/api/v1/events/ingest`).

## 3. Algorithmic Techniques (Pure-Python, Zero Heavy Dependencies)
1. **Dynamic Shannon Entropy**: Computes exact token entropy in bits over request payloads, filenames, and DNS queries ($H(X) = -\sum p(x) \log_2 p(x)$). Flags high-entropy anomalous exfiltration payloads ($H > 4.5$).
2. **Rolling Z-Score Tracking**: Employs online Welford variance tracking per entity/user for data transfer volume and connection frequencies ($Z = \frac{x - \mu}{\sigma}$). Detects statistically anomalous deviations ($|Z| \ge 3.0$).
3. **Pure-Python Isolation Forest**: Constructs random partitioning iTrees over continuous multi-dimensional feature vectors. Computes average path length $h(x)$ and outputs anomaly score $s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$. Outliers yield scores $> 0.60$.
4. **User & Entity Behavior Analytics (UEBA)**: Baselines normal operational hours and distinct destination graphs per source entity to flag off-hours access and lateral movement.

## 4. CLI Usage & Verification (Law 6)
```bash
# Execute standalone self-test suite (Shannon entropy, Z-score, Isolation Forest, and UEBA)
python -m modules.ml_detection.standalone --self-test

# Evaluate telemetry batch from JSON file
python -m modules.ml_detection.standalone --file /path/to/events.json

# Evaluate and forward findings directly to SentinelX REST API
python -m modules.ml_detection.standalone --file /path/to/events.json --forward --ingest-url http://localhost:8000/api/v1
```
