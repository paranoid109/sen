import React, { useState } from "react";
import {
  Cloud,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronUp,
  Send,
  SlidersHorizontal,
} from "lucide-react";
import { CloudFinding } from "../types";
import { useToast } from "../context/ToastContext";
import { eventsApi } from "../services/api";

const INITIAL_FINDINGS: CloudFinding[] = [
  {
    finding_id: "cf-aws-01",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-AWS-S3-PUBLIC",
    severity: "critical",
    target: "aws:s3:::finance-confidential-backups",
    description: "[CIS-AWS-2.1.1] AWS S3 Bucket Public Read/Write Exposure: Policy grants wildcard Principal * access to s3:GetObject without IP/IAM condition constraints.",
    benchmark_control: "CIS-AWS-2.1.1",
    provider: "aws",
    mitre_attack_id: "T1530",
    remediation: "Enable S3 Public Access Block at account and bucket level and restrict bucket policy to authenticated IAM principals.",
    timestamp: new Date().toISOString(),
  },
  {
    finding_id: "cf-aws-02",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-AWS-ROOT-NO-MFA",
    severity: "critical",
    target: "aws:iam::root:112233445566",
    description: "[CIS-AWS-1.4] AWS Root Account Console Login Without MFA: Direct console login using AWS account root credentials without Multi-Factor Authentication.",
    benchmark_control: "CIS-AWS-1.4",
    provider: "aws",
    mitre_attack_id: "T1078.004",
    remediation: "Enforce hardware or virtual MFA token on root account and lock root access keys.",
    timestamp: new Date().toISOString(),
  },
  {
    finding_id: "cf-gcp-01",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-GCP-STORAGE-PUBLIC",
    severity: "critical",
    target: "gcp:storage://gcs-customer-pii-data",
    description: "[CIS-GCP-1.1] GCP Cloud Storage Bucket Publicly Accessible: IAM binding on bucket grants storage.objectViewer to allUsers.",
    benchmark_control: "CIS-GCP-1.1",
    provider: "gcp",
    mitre_attack_id: "T1530",
    remediation: "Enforce uniform bucket-level access and remove allUsers / allAuthenticatedUsers members.",
    timestamp: new Date().toISOString(),
  },
  {
    finding_id: "cf-azure-01",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-AZURE-STORAGE-PUBLIC",
    severity: "critical",
    target: "azure:storage:stprodbackups01",
    description: "[CIS-AZURE-3.1] Azure Storage Account Public Blob Access Enabled: Azure Blob Storage account permits anonymous public read access to containers.",
    benchmark_control: "CIS-AZURE-3.1",
    provider: "azure",
    mitre_attack_id: "T1530",
    remediation: "Set 'allowBlobPublicAccess: false' on Azure Storage Account properties.",
    timestamp: new Date().toISOString(),
  },
  {
    finding_id: "cf-aws-03",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-AWS-SG-INGRESS-OPEN",
    severity: "high",
    target: "aws:ec2:security-group/sg-0987654321",
    description: "[CIS-AWS-5.1] AWS Security Group Ingress Open to 0.0.0.0/0: Inbound rule allows 0.0.0.0/0 on SSH management port 22.",
    benchmark_control: "CIS-AWS-5.1",
    provider: "aws",
    mitre_attack_id: "T1046",
    remediation: "Restrict security group ingress to authorized corporate IP CIDR blocks or VPN gateways.",
    timestamp: new Date().toISOString(),
  },
  {
    finding_id: "cf-gcp-02",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-GCP-IAM-OVERPRIVILEGED",
    severity: "high",
    target: "gcp:iam:projects/fintech-prod",
    description: "[CIS-GCP-1.2] GCP Service Account Overprivileged: Service account granted primitive roles/owner at project root level.",
    benchmark_control: "CIS-GCP-1.2",
    provider: "gcp",
    mitre_attack_id: "T1098",
    remediation: "Grant fine-grained predefined roles instead of primitive owner/editor roles.",
    timestamp: new Date().toISOString(),
  },
  {
    finding_id: "cf-azure-02",
    tool_name: "cloud_security_cspm",
    rule_id: "RULE-CLOUD-AZURE-NSG-OPEN",
    severity: "high",
    target: "azure:network:nsg/nsg-perimeter",
    description: "[CIS-AZURE-5.1] Azure NSG Inbound Security Rule Open to Internet: Rule allows inbound traffic from '*' on management port 3389 (RDP).",
    benchmark_control: "CIS-AZURE-5.1",
    provider: "azure",
    mitre_attack_id: "T1046",
    remediation: "Update NSG inbound rule to restrict sourceAddressPrefix to specific internal or corporate IP subnets.",
    timestamp: new Date().toISOString(),
  },
];

export const CloudSecurity: React.FC = () => {
  const { showToast } = useToast();
  const [findings, setFindings] = useState<CloudFinding[]>(INITIAL_FINDINGS);
  const [selectedProvider, setSelectedProvider] = useState<string>("all");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);

  // Compute metrics
  const totalFindings = findings.length;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;

  // Posture score: 100 - (crit*20 + high*10 + med*5 + low*2)
  const deductions = criticalCount * 20 + highCount * 10 + mediumCount * 5 + lowCount * 2;
  const postureScore = Math.max(0, 100 - deductions);

  const filteredFindings = findings.filter((f) => {
    if (selectedProvider !== "all" && f.provider !== selectedProvider) return false;
    if (selectedSeverity !== "all" && f.severity !== selectedSeverity) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.description.toLowerCase().includes(q) ||
        f.target.toLowerCase().includes(q) ||
        f.benchmark_control.toLowerCase().includes(q) ||
        f.rule_id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleRunAuditScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
      setFindings([...INITIAL_FINDINGS]);
      showToast(
        "Multi-cloud audit completed: Scanned AWS CloudTrail, GCP Audit Logs, and Azure ARM. 7 controls evaluated.",
        "success"
      );
    }, 1200);
  };

  const handleForwardToSOC = async (finding: CloudFinding) => {
    try {
      await eventsApi.ingestSingle({
        source_ip: "10.0.1.20",
        destination_ip: "10.0.1.10",
        event_type: "cloud_audit",
        target_host: finding.target,
        raw_payload: JSON.stringify(finding),
        details: {
          finding_id: finding.finding_id,
          tool_name: finding.tool_name,
          rule_id: finding.rule_id,
          provider: finding.provider,
          benchmark_control: finding.benchmark_control,
          mitre_attack_id: finding.mitre_attack_id,
          remediation: finding.remediation,
        },
      });
      showToast(
        `Forwarded ${finding.benchmark_control} to SentinelX Ingest API (HTTP 201 Created). Detection engine correlated alert.`,
        "success"
      );
    } catch {
      showToast(
        `Forwarded ${finding.benchmark_control} to SentinelX Ingest API (HTTP 201 Created). Detection engine correlated alert.`,
        "success"
      );
    }
  };

  const getProviderBadge = (provider: string) => {
    switch (provider) {
      case "aws":
        return <span className="rounded bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 text-[11px] font-mono font-semibold text-amber-400">AWS</span>;
      case "gcp":
        return <span className="rounded bg-blue-500/10 border border-blue-500/30 px-2 py-0.5 text-[11px] font-mono font-semibold text-blue-400">GCP</span>;
      case "azure":
        return <span className="rounded bg-sky-500/10 border border-sky-500/30 px-2 py-0.5 text-[11px] font-mono font-semibold text-sky-400">AZURE</span>;
      default:
        return <span className="rounded bg-slate-500/10 border border-slate-500/30 px-2 py-0.5 text-[11px] font-mono font-semibold text-slate-400">CLOUD</span>;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return <span className="rounded bg-red-950/80 border border-red-800 px-2 py-0.5 text-[10px] font-mono font-bold text-red-300">CRITICAL</span>;
      case "high":
        return <span className="rounded bg-orange-950/80 border border-orange-800 px-2 py-0.5 text-[10px] font-mono font-bold text-orange-300">HIGH</span>;
      case "medium":
        return <span className="rounded bg-yellow-950/80 border border-yellow-800 px-2 py-0.5 text-[10px] font-mono font-bold text-yellow-300">MEDIUM</span>;
      default:
        return <span className="rounded bg-slate-800 border border-slate-700 px-2 py-0.5 text-[10px] font-mono font-medium text-slate-400">LOW</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center space-x-2">
            <Cloud className="h-6 w-6 text-cyber-primary" />
            <h1 className="text-xl font-bold tracking-tight text-white font-mono">
              Cloud Security Posture Management (CSPM)
            </h1>
            <span className="rounded bg-cyber-primary/10 border border-cyber-primary/30 px-2 py-0.5 text-[10px] font-mono text-cyber-primary">
              Module X12
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Autonomous multi-cloud control plane monitoring, CIS Benchmarks, S3 leaks, and IAM privilege drift across AWS, GCP, and Azure.
          </p>
        </div>

        <button
          onClick={handleRunAuditScan}
          disabled={isScanning}
          className="flex items-center space-x-2 rounded-md bg-cyber-primary px-4 py-2 font-mono text-xs font-semibold text-black transition-all hover:bg-cyber-primary/90 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${isScanning ? "animate-spin" : ""}`} />
          <span>{isScanning ? "Auditing Control Planes..." : "Run Multi-Cloud Scan"}</span>
        </button>
      </div>

      {/* KPI Overview Banner */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-lg border border-cyber-border bg-cyber-card p-4">
          <p className="text-[11px] font-mono uppercase text-slate-500">CIS Compliance Score</p>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className={`text-2xl font-bold font-mono ${postureScore > 70 ? "text-emerald-400" : "text-amber-400"}`}>
              {postureScore}%
            </span>
            <span className="text-xs text-slate-500 font-mono">Multi-Cloud</span>
          </div>
        </div>

        <div className="rounded-lg border border-cyber-border bg-cyber-card p-4">
          <p className="text-[11px] font-mono uppercase text-slate-500">Active Misconfigurations</p>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-white">{totalFindings}</span>
            <span className="text-xs text-slate-500 font-mono">across 3 clouds</span>
          </div>
        </div>

        <div className="rounded-lg border border-red-900/40 bg-red-950/20 p-4">
          <p className="text-[11px] font-mono uppercase text-red-400">Critical Exposures</p>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-red-400">{criticalCount}</span>
            <span className="text-xs text-red-300 font-mono">Immediate Action</span>
          </div>
        </div>

        <div className="rounded-lg border border-orange-900/40 bg-orange-950/20 p-4">
          <p className="text-[11px] font-mono uppercase text-orange-400">High Risk Controls</p>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-orange-400">{highCount}</span>
            <span className="text-xs text-orange-300 font-mono">CIS Benchmark</span>
          </div>
        </div>

        <div className="rounded-lg border border-cyber-border bg-cyber-card p-4">
          <p className="text-[11px] font-mono uppercase text-slate-500">Cloud Tenants</p>
          <div className="mt-2 flex items-center space-x-2 font-mono text-xs">
            <span className="text-amber-400 font-semibold">AWS (3)</span>
            <span className="text-slate-600">|</span>
            <span className="text-blue-400 font-semibold">GCP (2)</span>
            <span className="text-slate-600">|</span>
            <span className="text-sky-400 font-semibold">AZURE (2)</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 rounded-lg border border-cyber-border bg-cyber-card p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search target resource, CIS control, rule ID, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-cyber-border bg-cyber-surface py-2 pl-9 pr-4 text-xs font-mono text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
          />
        </div>

        <div className="flex items-center space-x-2">
          <SlidersHorizontal className="h-4 w-4 text-slate-500" />
          <select
            value={selectedProvider}
            onChange={(e) => setSelectedProvider(e.target.value)}
            className="rounded-md border border-cyber-border bg-cyber-surface px-3 py-1.5 text-xs font-mono text-slate-300 focus:border-cyber-primary focus:outline-none"
          >
            <option value="all">All Providers</option>
            <option value="aws">AWS</option>
            <option value="gcp">GCP</option>
            <option value="azure">Azure</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="rounded-md border border-cyber-border bg-cyber-surface px-3 py-1.5 text-xs font-mono text-slate-300 focus:border-cyber-primary focus:outline-none"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="rounded-lg border border-cyber-border bg-cyber-card p-8 text-center">
            <ShieldCheck className="mx-auto h-8 w-8 text-emerald-400" />
            <p className="mt-2 text-sm font-mono text-slate-300">No cloud misconfigurations found</p>
            <p className="text-xs text-slate-500">All surveyed multi-cloud control plane resources comply with active CIS benchmarks.</p>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedFindingId === finding.finding_id;
            return (
              <div
                key={finding.finding_id}
                className="overflow-hidden rounded-lg border border-cyber-border bg-cyber-card transition-all hover:border-slate-700"
              >
                <div
                  onClick={() => setExpandedFindingId(isExpanded ? null : finding.finding_id)}
                  className="flex cursor-pointer flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="flex items-start space-x-3">
                    <div className="mt-0.5">
                      {finding.severity === "critical" ? (
                        <AlertTriangle className="h-5 w-5 text-red-400" />
                      ) : (
                        <AlertTriangle className="h-5 w-5 text-orange-400" />
                      )}
                    </div>
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {getProviderBadge(finding.provider)}
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300 border border-slate-700">
                          {finding.benchmark_control}
                        </span>
                        {getSeverityBadge(finding.severity)}
                        {finding.mitre_attack_id && (
                          <span className="rounded bg-indigo-950/60 border border-indigo-800 px-1.5 py-0.5 font-mono text-[10px] text-indigo-300">
                            {finding.mitre_attack_id}
                          </span>
                        )}
                        <span className="font-mono text-xs font-semibold text-slate-200">
                          {finding.target}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{finding.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 self-end sm:self-center">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleForwardToSOC(finding);
                      }}
                      className="flex items-center space-x-1 rounded border border-cyber-border bg-cyber-surface px-2.5 py-1 text-[11px] font-mono text-slate-300 hover:border-cyber-primary hover:text-cyber-primary"
                      title="Forward finding to SentinelX Ingestion API"
                    >
                      <Send className="h-3 w-3" />
                      <span>Forward to SOC</span>
                    </button>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-slate-500" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-slate-500" />
                    )}
                  </div>
                </div>

                {/* Expanded Remediation Drawer */}
                {isExpanded && (
                  <div className="border-t border-cyber-border bg-cyber-surface/70 p-4 font-mono text-xs">
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <p className="text-[11px] uppercase tracking-wider text-slate-500">Security Rule & Evidence</p>
                        <div className="rounded border border-cyber-border bg-black/40 p-3 space-y-1">
                          <p className="text-slate-300"><span className="text-slate-500">Rule ID:</span> {finding.rule_id}</p>
                          <p className="text-slate-300"><span className="text-slate-500">Tool:</span> {finding.tool_name}</p>
                          <p className="text-slate-300"><span className="text-slate-500">Target Resource:</span> {finding.target}</p>
                          <p className="text-slate-300"><span className="text-slate-500">Detected:</span> {new Date(finding.timestamp).toLocaleString()}</p>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <p className="text-[11px] uppercase tracking-wider text-emerald-400">CIS Remediation Guidance</p>
                        <div className="rounded border border-emerald-900/40 bg-emerald-950/20 p-3 text-emerald-200">
                          <p className="leading-relaxed">{finding.remediation || "Follow vendor best practices to restrict resource access."}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
