# Module X3: Endpoint Security Monitor

The Endpoint Security Monitor provides host-based intrusion detection, process lineage inspection, and File Integrity Monitoring (FIM).

## Capabilities

1. **LOLBAS & Obfuscated Command Execution (T1059.001, T1105)**
   - Flags base64/encoded PowerShell execution (`powershell.exe -enc ...`)
   - Flags download cradles (`certutil -urlcache -split ...`, `curl | bash`)
2. **Reverse Shell Spawns (T1059.004)**
   - Flags netcat interactive shells, bash socket redirects (`bash -i >&/dev/tcp/...`), and python pty sockets
3. **Privilege Escalation & Account Tampering (T1548.003)**
   - Flags modifications to `/etc/sudoers`, `/etc/shadow`, `visudo`, and wheel/root group additions
4. **File Integrity Monitoring (FIM) (T1565.001)**
   - Persistent SHA-256 baseline state snapshot tracking
   - Detects file modification or deletion in monitored sensitive directories

## Usage

### Self-Test
```bash
python -m modules.endpoint_security.standalone --self-test
```

### Ingest Auditd or Sysmon Logs
```bash
python -m modules.endpoint_security.standalone --file /var/log/audit/audit.log
```

### FIM Baseline & Scan
```bash
# Initialize snapshot
python -m modules.endpoint_security.standalone --fim-init /etc/passwd /etc/shadow /etc/sudoers --snapshot-file fim_baseline.json

# Check integrity
python -m modules.endpoint_security.standalone --fim-scan --snapshot-file fim_baseline.json
```

### Forward to SentinelX API
```bash
python -m modules.endpoint_security.standalone --file /var/log/audit/audit.log --ingest-url http://localhost:8000/api/v1/events/ingest --api-key sen_ingest_demo_key
```
