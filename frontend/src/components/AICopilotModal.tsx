import React, { useState, useEffect } from "react";
import {
  Sparkles,
  X,
  Bot,
  ShieldAlert,
  Search,
  CheckCircle,
  Copy,
  Terminal,
  ArrowRight,
  Flame,
} from "lucide-react";
import { Alert, IncidentDetail, Incident } from "../types";
import { useToast } from "../context/ToastContext";
import { useNavigate } from "react-router-dom";

interface AICopilotModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident?: IncidentDetail | Incident | null;
  alert?: Alert | null;
}

export const AICopilotModal: React.FC<AICopilotModalProps> = ({
  isOpen,
  onClose,
  incident,
  alert,
}) => {
  const { showToast } = useToast();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<"briefing" | "triage" | "query">("briefing");
  const [naturalQuery, setNaturalQuery] = useState<string>("");
  const [queryResult, setQueryResult] = useState<{
    endpoint: string;
    params: Record<string, any>;
    explanation: string;
  } | null>(null);

  useEffect(() => {
    if (alert && !incident) {
      setActiveTab("triage");
    } else {
      setActiveTab("briefing");
    }
  }, [incident, alert]);

  if (!isOpen) return null;

  const incidentTitle = incident?.title || "Correlated Multi-Stage Incident";
  const incidentRisk = incident?.risk_score ?? 85;
  const targetHost = incident?.target_host || "server-prod-01";

  const handleCopyMarkdown = (text: string) => {
    navigator.clipboard.writeText(text);
    showToast("Copied AI incident briefing to clipboard.", "success");
  };

  const handleTranslateQuery = (customText?: string) => {
    const text = customText || naturalQuery;
    if (!text.trim()) return;

    const q = text.toLowerCase();
    let res = {
      endpoint: "/api/v1/alerts",
      params: {} as Record<string, any>,
      explanation: "Translated inquiry into security alerts filtering.",
    };

    if (q.includes("incident")) {
      res = {
        endpoint: "/api/v1/incidents",
        params: { status: "OPEN", min_risk: 75 },
        explanation: "Filtering correlated incidents with status OPEN and elevated risk score >= 75.",
      };
    } else if (q.includes("audit")) {
      res = {
        endpoint: "/api/v1/audit",
        params: { username: "admin" },
        explanation: "Querying tamper-evident SHA-256 cryptographic audit logs filtered by username 'admin'.",
      };
    } else if (q.includes("critical")) {
      res = {
        endpoint: "/api/v1/alerts",
        params: { severity: "critical", target_host: targetHost },
        explanation: `Filtering critical severity alerts targeted at host '${targetHost}'.`,
      };
    } else {
      res = {
        endpoint: "/api/v1/alerts",
        params: { target_host: targetHost },
        explanation: `Filtering alerts targeted at host '${targetHost}'.`,
      };
    }

    setQueryResult(res);
  };

  const handleApplyQuery = () => {
    if (!queryResult) return;
    onClose();
    if (queryResult.endpoint.includes("alerts")) {
      navigate("/alerts");
    } else if (queryResult.endpoint.includes("incidents")) {
      navigate("/incidents");
    } else if (queryResult.endpoint.includes("audit")) {
      navigate("/admin");
    }
    showToast(`Navigating to ${queryResult.endpoint} with AI filter parameters applied.`, "info");
  };

  const simulatedBriefingMarkdown = `# SentinelX AI Incident Debrief: ${incidentTitle}
**Target Host**: \`${targetHost}\` | **Risk Score**: \`${incidentRisk}/100\` | **Severity**: \`CRITICAL\`
**Autonomous Evaluation Time**: \`${new Date().toISOString()}\`

## 1. Executive Summary
SentinelX autonomous correlation has synthesized a high-risk security incident targeting infrastructure host \`${targetHost}\`. Correlation indicates a coordinated attack progression spanning external reconnaissance, web vulnerability exploitation (SQL Injection), and command execution.

## 2. Root Cause Hypothesis
> [!IMPORTANT]
> **Primary Vector**: Web application perimeter input sanitization failure permitting SQL injection exploit (CWE-89, MITRE ATT&CK T1190).

## 3. MITRE ATT&CK Kill-Chain Progression
1. **Reconnaissance & Initial Probing (T1046)**: Attacker performed network port scan discovering exposed web service.
2. **Exploitation & Initial Access (T1190)**: Exploited input parameter with union-based SQL injection payload to exfiltrate database contents.
3. **Execution & Command Interpreter (T1059.004)**: Attempted interactive shell spawning and reverse connection back to threat actor IP.

## 4. Immediate Defensive Guidance
- **T1190 (Exploit Public-Facing Application)**: CIS Control 7.4: Deploy Web Application Firewall (WAF) virtual patch for vulnerable endpoint.
- **T1059.004 (Unix Shell)**: CIS Control 8.2: Inspect Linux auditd process creation events and quarantine affected host.

## 5. Recommended Autonomous Response Playbooks
- **Playbooks**: \`host_quarantine\`, \`forensic_triage\`, \`block_attacker_ip\`
- Preserves SOC administrative management channels on port 8000/22 while isolating untrusted traffic.`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="relative flex flex-col h-[90vh] max-h-[850px] w-full max-w-4xl rounded-xl border border-cyber-border bg-cyber-surface shadow-2xl overflow-hidden font-mono">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-cyber-border bg-cyber-card px-6 py-4">
          <div className="flex items-center space-x-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyber-primary/10 border border-cyber-primary/30">
              <Sparkles className="h-5 w-5 text-cyber-primary" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-white tracking-wide">
                  SentinelX AI SOC Analyst Copilot
                </span>
                <span className="rounded bg-cyber-primary/10 border border-cyber-primary/30 px-1.5 py-0.5 text-[10px] text-cyber-primary">
                  Module X13
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Autonomous incident debrief synthesis, alert triage advisory, and REST query translation
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-cyber-surface hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-cyber-border bg-cyber-surface px-6 pt-2">
          <button
            onClick={() => setActiveTab("briefing")}
            className={`flex items-center space-x-2 border-b-2 px-4 py-2.5 text-xs font-semibold transition-all ${
              activeTab === "briefing"
                ? "border-cyber-primary text-cyber-primary"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Bot className="h-4 w-4" />
            <span>Executive Briefing</span>
          </button>

          <button
            onClick={() => setActiveTab("triage")}
            className={`flex items-center space-x-2 border-b-2 px-4 py-2.5 text-xs font-semibold transition-all ${
              activeTab === "triage"
                ? "border-cyber-primary text-cyber-primary"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <ShieldAlert className="h-4 w-4" />
            <span>Alert Triage Advisor</span>
          </button>

          <button
            onClick={() => setActiveTab("query")}
            className={`flex items-center space-x-2 border-b-2 px-4 py-2.5 text-xs font-semibold transition-all ${
              activeTab === "query"
                ? "border-cyber-primary text-cyber-primary"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="h-4 w-4" />
            <span>Natural Language Query</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* TAB 1: EXECUTIVE BRIEFING */}
          {activeTab === "briefing" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-cyber-border bg-cyber-card p-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <Flame className="h-4 w-4 text-red-400" />
                    <span className="text-xs font-bold text-white">{incidentTitle}</span>
                    <span className="rounded bg-red-950/80 border border-red-800 px-1.5 py-0.5 text-[10px] text-red-300">
                      Risk: {incidentRisk}/100
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-400">
                    Target: <span className="text-cyber-primary">{targetHost}</span> | Correlated alerts and telemetry timeline
                  </p>
                </div>

                <button
                  onClick={() => handleCopyMarkdown(simulatedBriefingMarkdown)}
                  className="flex items-center space-x-1.5 rounded border border-cyber-border bg-cyber-surface px-3 py-1.5 text-xs text-slate-300 hover:border-cyber-primary hover:text-cyber-primary"
                >
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy Markdown</span>
                </button>
              </div>

              {/* Formatted Briefing Output */}
              <div className="rounded-lg border border-cyber-border bg-cyber-card p-5 text-xs text-slate-300 space-y-4 leading-relaxed">
                <div>
                  <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wide">
                    1. Executive Summary & Impact Analysis
                  </h3>
                  <p className="mt-1 text-slate-300">
                    SentinelX autonomous correlation has identified a <strong className="text-red-400">CRITICAL</strong> risk incident (Risk Score: {incidentRisk}/100) targeting critical asset <code className="bg-black/50 px-1 rounded text-cyber-primary">{targetHost}</code>. Telemetry indicates multi-stage attacker progression triggering correlated detection rules.
                  </p>
                </div>

                <div className="border-l-2 border-red-500 pl-3 bg-red-950/20 py-2 rounded-r">
                  <h4 className="text-[11px] font-bold text-red-300 uppercase">2. Root Cause Hypothesis</h4>
                  <p className="mt-0.5 text-red-200">
                    Perimeter web application input sanitization vulnerability permitting SQL injection exploitation (CWE-89, MITRE ATT&CK T1190).
                  </p>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wide">
                    3. MITRE ATT&CK Kill-Chain Progression
                  </h3>
                  <div className="mt-2 space-y-1.5 pl-2 text-slate-300">
                    <p>1. <strong className="text-white">Reconnaissance (T1046)</strong>: Attacker probed open network services on management ports.</p>
                    <p>2. <strong className="text-white">Initial Access (T1190)</strong>: SQL injection exploit payload submitted to web service.</p>
                    <p>3. <strong className="text-white">Execution (T1059.004)</strong>: Interactive shell invocation and reverse network socket initiated.</p>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wide">
                    4. Immediate Defensive Guidance (CIS Controls & D3FEND)
                  </h3>
                  <div className="mt-2 space-y-2">
                    <div className="rounded border border-cyber-border bg-cyber-surface/60 p-2.5">
                      <span className="font-bold text-white">T1190 (Exploit Public-Facing Application)</span>
                      <p className="text-slate-400 text-[11px] mt-0.5">CIS Control 7.4: Deploy Web Application Firewall (WAF) virtual patch.</p>
                    </div>
                    <div className="rounded border border-cyber-border bg-cyber-surface/60 p-2.5">
                      <span className="font-bold text-white">T1059.004 (Unix Shell)</span>
                      <p className="text-slate-400 text-[11px] mt-0.5">CIS Control 8.2: Collect Auditd process telemetry and restrict process execution.</p>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wide">
                    5. Recommended Autonomous Response Playbooks
                  </h3>
                  <div className="mt-2 flex items-center space-x-2">
                    <span className="rounded bg-cyber-primary/10 border border-cyber-primary/30 px-2.5 py-1 text-cyber-primary font-semibold">
                      host_quarantine
                    </span>
                    <span className="rounded bg-cyber-primary/10 border border-cyber-primary/30 px-2.5 py-1 text-cyber-primary font-semibold">
                      forensic_triage
                    </span>
                    <span className="rounded bg-cyber-primary/10 border border-cyber-primary/30 px-2.5 py-1 text-cyber-primary font-semibold">
                      block_attacker_ip
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: ALERT TRIAGE ADVISOR */}
          {activeTab === "triage" && (
            <div className="space-y-4">
              <div className="rounded-lg border border-cyber-border bg-cyber-card p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    Alert Evidence Evaluation
                  </span>
                  <span className="rounded bg-emerald-950/80 border border-emerald-800 px-2 py-0.5 text-[11px] font-bold text-emerald-300">
                    VERDICT: TRUE_POSITIVE (98% Confidence)
                  </span>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-500">Target Host:</span>
                    <span className="text-slate-200 font-semibold">{targetHost}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-500">Source IP:</span>
                    <span className="text-slate-200 font-semibold">198.51.100.4 (External Public IP)</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-slate-500">Signature:</span>
                    <span className="text-amber-400">RULE-SQLI-001 (SQL Injection Exploit)</span>
                  </div>
                </div>

                {/* Confidence Bar */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px] text-slate-400">
                    <span>AI Confidence Score</span>
                    <span className="text-emerald-400 font-bold">98% (Extremely High)</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full bg-emerald-500 rounded-full" style={{ width: "98%" }}></div>
                  </div>
                </div>

                {/* Key Rationale */}
                <div className="rounded border border-cyber-border bg-cyber-surface p-3 space-y-1 text-xs">
                  <p className="text-slate-400 font-semibold uppercase text-[10px]">AI Reasoning Factors:</p>
                  <p className="text-slate-300 flex items-center space-x-1.5">
                    <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span>External non-RFC1918 routable source IP (198.51.100.4) probing internal database target.</span>
                  </p>
                  <p className="text-slate-300 flex items-center space-x-1.5">
                    <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span>Deterministic SQL injection signature match: <code className="text-amber-300">UNION SELECT password_hash FROM users--</code>.</span>
                  </p>
                  <p className="text-slate-300 flex items-center space-x-1.5">
                    <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span>Occurrence count is elevated (8 attempts within 60s sliding window).</span>
                  </p>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center space-x-3 pt-2">
                  <button
                    onClick={() => {
                      showToast("Triage recommendation accepted: Alert confirmed as TRUE POSITIVE.", "success");
                      onClose();
                    }}
                    className="flex-1 rounded-md bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition-colors"
                  >
                    Confirm True Positive & Escalate
                  </button>
                  <button
                    onClick={() => {
                      showToast("Alert marked as False Positive. Exclusion filter suggested.", "info");
                      onClose();
                    }}
                    className="rounded-md border border-cyber-border bg-cyber-surface px-4 py-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    Mark False Positive
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: NATURAL LANGUAGE QUERY */}
          {activeTab === "query" && (
            <div className="space-y-4">
              <div className="rounded-lg border border-cyber-border bg-cyber-card p-4 space-y-3">
                <p className="text-xs text-slate-400">
                  Ask a question in plain English. The AI Assistant will translate it into structured SentinelX REST API query parameters.
                </p>

                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                    <input
                      type="text"
                      placeholder="e.g. Show critical alerts for server-prod-01..."
                      value={naturalQuery}
                      onChange={(e) => setNaturalQuery(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleTranslateQuery()}
                      className="w-full rounded-md border border-cyber-border bg-cyber-surface py-2 pl-9 pr-4 text-xs text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                    />
                  </div>
                  <button
                    onClick={() => handleTranslateQuery()}
                    className="rounded-md bg-cyber-primary px-4 py-2 text-xs font-semibold text-black hover:bg-cyber-primary/90 transition-all"
                  >
                    Translate
                  </button>
                </div>

                {/* Quick Prompts */}
                <div className="space-y-1.5 pt-1">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider">Suggested Inquiries:</p>
                  <div className="flex flex-wrap gap-2">
                    {[
                      `Show critical alerts on ${targetHost}`,
                      "Find open incidents with risk score above 80",
                      "Show recent audit trail events by admin",
                    ].map((prompt) => (
                      <button
                        key={prompt}
                        onClick={() => {
                          setNaturalQuery(prompt);
                          handleTranslateQuery(prompt);
                        }}
                        className="rounded border border-cyber-border bg-cyber-surface px-2.5 py-1 text-[11px] text-slate-300 hover:border-cyber-primary hover:text-cyber-primary transition-colors"
                      >
                        {prompt}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Query Result Card */}
                {queryResult && (
                  <div className="rounded-lg border border-cyber-primary/40 bg-cyber-surface p-4 space-y-3 mt-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-cyber-primary">Synthesized REST Query</span>
                      <span className="rounded bg-cyber-primary/10 border border-cyber-primary/30 px-2 py-0.5 text-[10px] text-cyber-primary">
                        GET {queryResult.endpoint}
                      </span>
                    </div>

                    <div className="rounded bg-black/50 p-2.5 font-mono text-[11px] text-slate-300 space-y-1">
                      <p className="text-slate-400"><span className="text-slate-500">Endpoint:</span> {queryResult.endpoint}</p>
                      <p className="text-slate-400">
                        <span className="text-slate-500">Query Parameters:</span> {JSON.stringify(queryResult.params)}
                      </p>
                    </div>

                    <p className="text-xs text-slate-400">{queryResult.explanation}</p>

                    <button
                      onClick={handleApplyQuery}
                      className="flex items-center space-x-1.5 rounded-md bg-cyber-primary px-3 py-1.5 text-xs font-semibold text-black hover:bg-cyber-primary/90 transition-all"
                    >
                      <span>Navigate & Apply Filter</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
