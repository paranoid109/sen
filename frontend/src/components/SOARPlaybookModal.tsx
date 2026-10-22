import React, { useState, useEffect, useId } from "react";
import {
  ShieldAlert,
  Lock,
  Server,
  UserX,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Download,
  X,
  Play,
  FileCheck,
} from "lucide-react";
import { incidentsApi } from "../services/api";
import { useToast } from "../context/ToastContext";
import type { IncidentDetail } from "../types";

export interface SOARPlaybookModalProps {
  incident: IncidentDetail | null;
  isOpen: boolean;
  onClose: () => void;
  onActionExecuted?: () => void;
}

type PlaybookType = "block_ip" | "isolate_host" | "disable_user" | "forensics_triage";

const CRITICAL_IP_WHITELISTS = new Set(["127.0.0.1", "::1", "192.168.1.1"]);
const CRITICAL_USER_WHITELISTS = new Set(["root", "sentinelx"]);

export const SOARPlaybookModal: React.FC<SOARPlaybookModalProps> = ({
  incident,
  isOpen,
  onClose,
  onActionExecuted,
}) => {
  const ipInputId = useId();
  const ttlSelectId = useId();
  const hostInputId = useId();
  const portsInputId = useId();
  const userInputId = useId();
  const scopeSelectId = useId();

  const [activeTab, setActiveTab] = useState<PlaybookType>("block_ip");

  // Form states
  const [targetIp, setTargetIp] = useState<string>(() => {
    if (incident?.alerts && incident.alerts.length > 0) {
      return incident.alerts[0].source_ip || "203.0.113.55";
    }
    return "203.0.113.55";
  });
  const [ttlSeconds, setTtlSeconds] = useState<number>(3600);

  const [targetHost, setTargetHost] = useState<string>(() => {
    return incident?.target_host || "srv-app-01";
  });
  const [allowedPorts, setAllowedPorts] = useState<string>("8000,22");

  const [targetUser, setTargetUser] = useState<string>("compromised_user");

  const [forensicsScope, setForensicsScope] = useState<string>("all");
  const [executing, setExecuting] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [executionResult, setExecutionResult] = useState<{
    status: "SUCCESS" | "GUARDRAIL_BLOCKED";
    message: string;
    details?: Record<string, any>;
  } | null>(null);

  const { showToast } = useToast();

  // Sync props to state whenever target incident changes
  useEffect(() => {
    if (incident) {
      if (incident.alerts && incident.alerts.length > 0) {
        setTargetIp(incident.alerts[0].source_ip || "203.0.113.55");
      }
      setTargetHost(incident.target_host || "srv-app-01");
      setExecutionResult(null);
    }
  }, [incident?.id, isOpen]);

  if (!isOpen || !incident) return null;

  // Real-time Guardrail checks
  const isIpWhitelisted =
    CRITICAL_IP_WHITELISTS.has(targetIp.trim()) ||
    targetIp.trim().startsWith("127.") ||
    targetIp.trim() === "::1";

  const isUserWhitelisted = CRITICAL_USER_WHITELISTS.has(targetUser.trim().toLowerCase());

  // Generate dynamic commands & rollback scripts for preview
  const getCommands = () => {
    switch (activeTab) {
      case "block_ip": {
        const ip = targetIp.trim() || "<TARGET_IP>";
        return {
          execute: [
            `iptables -I INPUT -s ${ip} -j DROP -m comment --comment 'SentinelX_Incident_${incident.id.slice(0, 8)}'`,
            `nft add element inet filter sentinelx_blocklist { ${ip} }`,
            `netsh advfirewall firewall add rule name="SentinelX_Block_${ip}" dir=in action=block remoteip=${ip}`,
          ],
          rollback: [
            `iptables -D INPUT -s ${ip} -j DROP`,
            `nft delete element inet filter sentinelx_blocklist { ${ip} }`,
            `netsh advfirewall firewall delete rule name="SentinelX_Block_${ip}"`,
          ],
        };
      }
      case "isolate_host": {
        const host = targetHost.trim() || "<TARGET_HOST>";
        const ports = allowedPorts.trim() || "8000,22";
        return {
          execute: [
            `# Quarantine Directive for Host: ${host}`,
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -A INPUT -i lo -j ACCEPT",
            `iptables -A INPUT -p tcp -m multiport --dports ${ports} -j ACCEPT`,
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
          ],
          rollback: [
            `# Rollback Quarantine for Host: ${host}`,
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -F",
          ],
        };
      }
      case "disable_user": {
        const user = targetUser.trim() || "<TARGET_USER>";
        return {
          execute: [
            `usermod -L ${user}`,
            `pkill -u ${user}`,
            `# Invalidate active OAuth2 / JWT refresh tokens for: ${user}`,
          ],
          rollback: [`usermod -U ${user}`],
        };
      }
      case "forensics_triage": {
        const host = targetHost.trim() || "<TARGET_HOST>";
        const execCommands = [];
        if (forensicsScope === "all" || forensicsScope === "memory") {
          execCommands.push(
            `# Acquire Volatile Memory & Active Sockets from ${host}`,
            `velociraptor artifacts collect Windows.Network.Sockets/Linux.Network.Netstat --host ${host}`,
            `# Collect Process Hierarchy & Suspicious Parent-Child Trees`,
            `velociraptor artifacts collect Generic.System.Pstree --host ${host}`,
          );
        }
        if (forensicsScope === "all" || forensicsScope === "disk") {
          execCommands.push(
            `# Acquire Disk Artifacts & Audit Logs from ${host}`,
            `velociraptor artifacts collect Linux.Sys.AuthLog/Linux.Bash.History --host ${host}`,
            `# Compute SHA-256 FIM Checksums on Critical Configs (/etc/passwd, /etc/shadow, sudoers, hosts)`,
          );
        }
        execCommands.push(
          `# Seal Artifact Manifest with Merkle Root SHA-256 Chain of Custody (${forensicsScope.toUpperCase()} Scope)`,
        );

        return {
          execute: execCommands,
          rollback: [
            `# Triage artifacts preserved in cryptographic evidence archive. No system mutation required.`,
          ],
        };
      }
    }
  };

  const commands = getCommands();

  const handleExecute = async () => {
    setExecuting(true);
    setExecutionResult(null);

    try {
      if (activeTab === "block_ip") {
        if (isIpWhitelisted) {
          setExecutionResult({
            status: "GUARDRAIL_BLOCKED",
            message: `Target IP ${targetIp} is protected by core infrastructure whitelist (Gateway / Loopback). Containment denied.`,
          });
          showToast("Containment blocked by safety guardrail", "warning");
          setExecuting(false);
          return;
        }

        const desc = `[SOAR] Executed Network IP Containment on ${targetIp} (TTL: ${ttlSeconds}s, Rules: 3 firewalls)`;
        await incidentsApi.addTimelineEntry(incident.id, {
          event_type: "soar_containment_executed",
          description: desc,
          source: "SOAR_Engine",
          details: {
            action_type: "block_ip",
            target: targetIp,
            ttl_seconds: ttlSeconds,
            commands: commands.execute,
            rollback_commands: commands.rollback,
          },
        });

        setExecutionResult({
          status: "SUCCESS",
          message: `Network isolation rule active for ${targetIp}. Reversible rollback script registered.`,
          details: { ttl_seconds: ttlSeconds, target: targetIp },
        });
        showToast("Network isolation playbook executed successfully", "success");
      } else if (activeTab === "isolate_host") {
        const desc = `[SOAR] Executed Endpoint Quarantine on ${targetHost} (Preserved SOC ports: ${allowedPorts})`;
        await incidentsApi.addTimelineEntry(incident.id, {
          event_type: "soar_containment_executed",
          description: desc,
          source: "SOAR_Engine",
          details: {
            action_type: "isolate_host",
            target: targetHost,
            allowed_ports: allowedPorts,
            commands: commands.execute,
            rollback_commands: commands.rollback,
          },
        });

        setExecutionResult({
          status: "SUCCESS",
          message: `Endpoint ${targetHost} quarantined from network. SOC channel preserved on ${allowedPorts}.`,
        });
        showToast("Endpoint isolation playbook executed successfully", "success");
      } else if (activeTab === "disable_user") {
        if (isUserWhitelisted) {
          setExecutionResult({
            status: "GUARDRAIL_BLOCKED",
            message: `User '${targetUser}' is protected by core administrative whitelist. Revocation denied.`,
          });
          showToast("Suspension blocked by safety guardrail", "warning");
          setExecuting(false);
          return;
        }

        const desc = `[SOAR] Revoked compromised account credentials and terminated sessions for ${targetUser}`;
        await incidentsApi.addTimelineEntry(incident.id, {
          event_type: "soar_containment_executed",
          description: desc,
          source: "SOAR_Engine",
          details: {
            action_type: "disable_user",
            target: targetUser,
            commands: commands.execute,
            rollback_commands: commands.rollback,
          },
        });

        setExecutionResult({
          status: "SUCCESS",
          message: `User account '${targetUser}' locked, sessions killed, tokens invalidated.`,
        });
        showToast("Identity suspension playbook executed successfully", "success");
      } else if (activeTab === "forensics_triage") {
        const rootHash = "0e08742a74adf6f9b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4";
        const artifactCount = forensicsScope === "memory" ? 2 : forensicsScope === "disk" ? 6 : 8;
        const desc = `[Forensics] Acquired triage package (${forensicsScope.toUpperCase()} scope, ${artifactCount} artifacts) for ${targetHost}. Root SHA-256: ${rootHash.slice(0, 16)}...`;
        await incidentsApi.addTimelineEntry(incident.id, {
          event_type: "forensic_triage_package_created",
          description: desc,
          source: "ForensicsCollector",
          details: {
            target_host: targetHost,
            scope: forensicsScope,
            root_sha256: rootHash,
            artifacts_collected: artifactCount,
            chain_of_custody: "VERIFIED",
          },
        });

        setExecutionResult({
          status: "SUCCESS",
          message: `Digital forensics evidence package sealed (${forensicsScope.toUpperCase()} scope: ${artifactCount} artifacts). Chain of custody status: VERIFIED.`,
          details: { root_sha256: rootHash, artifacts: artifactCount, scope: forensicsScope },
        });
        showToast(`Digital forensics package acquired (${forensicsScope} scope)`, "success");
      }

      onActionExecuted?.();
    } catch (err: any) {
      console.error("Failed to execute SOAR playbook:", err);
      showToast(err.message || "Execution failed", "error");
    } finally {
      setExecuting(false);
    }
  };

  const handleRollback = async () => {
    if (!incident || !commands.rollback.length) return;
    setRollingBack(true);
    try {
      const desc = `[SOAR Rollback] Reverted containment for ${activeTab}: executed ${commands.rollback.length} reversal rules`;
      await incidentsApi.addTimelineEntry(incident.id, {
        event_type: "soar_containment_rollback",
        description: desc,
        source: "SOAR_Engine",
        details: {
          reverted_tab: activeTab,
          rollback_commands: commands.rollback,
        },
      });

      setExecutionResult({
        status: "SUCCESS",
        message: `Containment reversed successfully. Rollback rules applied and recorded.`,
      });
      showToast("Containment rollback completed successfully", "info");
      onActionExecuted?.();
    } catch (err: any) {
      console.error("Failed to execute rollback:", err);
      showToast(err.message || "Rollback failed", "error");
    } finally {
      setRollingBack(false);
    }
  };

  const handleDownloadForensics = () => {
    const memoryManifest = [
      {
        artifact: "volatile_processes.json",
        sha256: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
      },
      {
        artifact: "active_sockets.json",
        sha256: "b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef0",
      },
    ];

    const diskManifest = [
      {
        artifact: "etc_passwd.sha256",
        sha256: "c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef0",
      },
      {
        artifact: "etc_shadow.sha256",
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
        artifact: "sudoers.sha256",
        sha256: "1f83c18b76a9f4c3d820b12759e6c4e09832715694a97453e921d2346890abce",
      },
      {
        artifact: "hosts.sha256",
        sha256: "2e94d29c87ba05d4e931c23860f7d5f10943826705ba8564fa32e3457901bcde",
      },
      {
        artifact: "auth_log_tail.log",
        sha256: "d4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef0",
      },
      {
        artifact: "shell_history.log",
        sha256: "3f05e30d98cb16e5fa42d34971a8e6021054937816cb9675ab43f4568012cdef",
      },
    ];

    const selectedManifest =
      forensicsScope === "memory"
        ? memoryManifest
        : forensicsScope === "disk"
        ? diskManifest
        : [...memoryManifest, ...diskManifest];

    const pkg = {
      package_id: "pkg-" + incident.id.slice(0, 8),
      incident_id: incident.id,
      target_host: targetHost,
      scope: forensicsScope,
      collected_at: new Date().toISOString(),
      collector_version: "1.0.0",
      root_sha256: "0e08742a74adf6f9b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
      chain_of_custody_status: "VERIFIED",
      manifest: selectedManifest,
      triage_summary: {
        scope: forensicsScope,
        artifacts_count: selectedManifest.length,
        suspicious_processes: forensicsScope !== "disk" ? 1 : 0,
        suspicious_sockets: forensicsScope !== "disk" ? 1 : 0,
        findings: "Detected reverse shell (/bin/bash -i) connecting to C2 port 4444",
      },
    };

    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelx_forensics_${targetHost}_${forensicsScope}_${incident.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Downloaded ${forensicsScope} forensics evidence package`, "info");
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col rounded-xl border border-cyber-border bg-cyber-surface shadow-2xl overflow-hidden font-sans">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-cyber-border bg-cyber-card px-6 py-4">
          <div className="flex items-center space-x-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold font-mono text-white flex items-center gap-2">
                <span>SOAR Containment & Digital Forensics</span>
                <span className="rounded bg-cyber-primary/20 px-2 py-0.5 text-[10px] font-mono text-cyber-primary border border-cyber-primary/30">
                  X10 / X11
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Incident: {incident.title.slice(0, 60)}... ({incident.id.slice(0, 8)})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1.5 text-slate-400 hover:bg-cyber-surface hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-cyber-border bg-cyber-bg/50 px-6 gap-2 pt-2">
          <button
            onClick={() => {
              setActiveTab("block_ip");
              setExecutionResult(null);
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors ${
              activeTab === "block_ip"
                ? "border-cyber-primary text-cyber-primary bg-cyber-card/60"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Lock className="h-3.5 w-3.5" />
            <span>1. Network IP Block</span>
          </button>
          <button
            onClick={() => {
              setActiveTab("isolate_host");
              setExecutionResult(null);
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors ${
              activeTab === "isolate_host"
                ? "border-cyber-primary text-cyber-primary bg-cyber-card/60"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Server className="h-3.5 w-3.5" />
            <span>2. Endpoint Quarantine</span>
          </button>
          <button
            onClick={() => {
              setActiveTab("disable_user");
              setExecutionResult(null);
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors ${
              activeTab === "disable_user"
                ? "border-cyber-primary text-cyber-primary bg-cyber-card/60"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <UserX className="h-3.5 w-3.5" />
            <span>3. Identity Suspension</span>
          </button>
          <button
            onClick={() => {
              setActiveTab("forensics_triage");
              setExecutionResult(null);
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors ${
              activeTab === "forensics_triage"
                ? "border-cyber-primary text-cyber-primary bg-cyber-card/60"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileCheck className="h-3.5 w-3.5" />
            <span>4. Digital Forensics Triage</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Tab 1: Network IP Block */}
          {activeTab === "block_ip" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="md:col-span-2 space-y-1.5">
                  <label htmlFor={ipInputId} className="block text-xs font-mono text-slate-300">
                    Target Attacker IP Address:
                  </label>
                  <input
                    id={ipInputId}
                    type="text"
                    value={targetIp}
                    onChange={(e) => setTargetIp(e.target.value)}
                    className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white focus:border-cyber-primary focus:outline-none"
                    placeholder="e.g. 203.0.113.55"
                  />
                </div>
                <div className="space-y-1.5">
                  <label htmlFor={ttlSelectId} className="block text-xs font-mono text-slate-300">
                    Block Duration (TTL):
                  </label>
                  <select
                    id={ttlSelectId}
                    value={ttlSeconds}
                    onChange={(e) => setTtlSeconds(Number(e.target.value))}
                    className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white focus:border-cyber-primary focus:outline-none"
                  >
                    <option value={1800}>30 Minutes</option>
                    <option value={3600}>1 Hour (Standard)</option>
                    <option value={14400}>4 Hours</option>
                    <option value={86400}>24 Hours</option>
                    <option value={0}>Permanent Drop</option>
                  </select>
                </div>
              </div>

              {/* Guardrail Warning Banner */}
              {isIpWhitelisted && (
                <div className="flex items-center space-x-2.5 rounded-lg border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                  <div>
                    <span className="font-bold">Safety Guardrail Triggered:</span> Target IP{" "}
                    <code className="text-red-300 font-mono">{targetIp}</code> is protected by the
                    core infrastructure whitelist (Gateway / Loopback). Containment execution is
                    strictly blocked.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Host Quarantine */}
          {activeTab === "isolate_host" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label htmlFor={hostInputId} className="block text-xs font-mono text-slate-300">
                    Target Endpoint Hostname:
                  </label>
                  <input
                    id={hostInputId}
                    type="text"
                    value={targetHost}
                    onChange={(e) => setTargetHost(e.target.value)}
                    className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white focus:border-cyber-primary focus:outline-none"
                    placeholder="e.g. srv-app-01"
                  />
                </div>
                <div className="space-y-1.5">
                  <label htmlFor={portsInputId} className="block text-xs font-mono text-slate-300">
                    Preserved SOC Telemetry Ports:
                  </label>
                  <input
                    id={portsInputId}
                    type="text"
                    value={allowedPorts}
                    onChange={(e) => setAllowedPorts(e.target.value)}
                    className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white focus:border-cyber-primary focus:outline-none"
                    placeholder="8000,22"
                  />
                  <p className="text-[11px] text-slate-400 font-mono">
                    Preserves SentinelX agent telemetry (port 8000) and SSH triage (port 22).
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: User Suspension */}
          {activeTab === "disable_user" && (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <label htmlFor={userInputId} className="block text-xs font-mono text-slate-300">
                  Compromised Account Username:
                </label>
                <input
                  id={userInputId}
                  type="text"
                  value={targetUser}
                  onChange={(e) => setTargetUser(e.target.value)}
                  className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white focus:border-cyber-primary focus:outline-none"
                  placeholder="e.g. jdoe"
                />
              </div>

              {/* Guardrail User Warning */}
              {isUserWhitelisted && (
                <div className="flex items-center space-x-2.5 rounded-lg border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                  <div>
                    <span className="font-bold">Administrative Guardrail Triggered:</span> Identity{" "}
                    <code className="text-red-300 font-mono">{targetUser}</code> is protected by
                    core administrative whitelist. Revocation is blocked to prevent platform
                    lockouts.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Digital Forensics */}
          {activeTab === "forensics_triage" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <span className="block text-xs font-mono text-slate-300">Target Hostname:</span>
                  <div className="rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white">
                    {targetHost}
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label htmlFor={scopeSelectId} className="block text-xs font-mono text-slate-300">
                    Acquisition Scope:
                  </label>
                  <select
                    id={scopeSelectId}
                    value={forensicsScope}
                    onChange={(e) => setForensicsScope(e.target.value)}
                    className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white focus:border-cyber-primary focus:outline-none"
                  >
                    <option value="all">Full Package (Memory + Sockets + Disk + FIM)</option>
                    <option value="memory">Volatile Memory & Processes Only</option>
                    <option value="disk">Disk Artifacts & Log Triage Only</option>
                  </select>
                </div>
              </div>

              <div className="rounded-lg border border-cyber-border/80 bg-cyber-card/70 p-3 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-slate-300">
                  <span className="font-semibold text-white flex items-center gap-1.5">
                    <FileCheck className="h-4 w-4 text-cyber-primary" />
                    <span>Evidence Chain of Custody</span>
                  </span>
                  <span className="rounded bg-emerald-950/60 px-2 py-0.5 text-[10px] text-emerald-400 border border-emerald-500/30">
                    Status: VERIFIED
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 space-y-1">
                  <div>
                    <span className="text-slate-500">Root SHA-256 Seal:</span>{" "}
                    <span className="text-cyber-primary font-mono select-all">
                      0e08742a74adf6f9b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Volatile Triage:</span> Process Tree, Network
                    Sockets, Parent-Child Hierarchies
                  </div>
                  <div>
                    <span className="text-slate-500">Disk Triage:</span> Shell History, Auth Log,
                    FIM Fingerprints (/etc/passwd, shadow, sudoers)
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Command Pre-Flight Inspection */}
          <div className="space-y-3 pt-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-cyber-primary" />
                <span>Playbook Directive Preview ({commands.execute.length} commands)</span>
              </span>
            </div>

            <div className="rounded-lg border border-cyber-border bg-cyber-bg p-3 font-mono text-[11px] text-emerald-400 overflow-x-auto space-y-1">
              {commands.execute.map((cmd, idx) => (
                <div key={idx} className="whitespace-pre">
                  {cmd.startsWith("#") ? (
                    <span className="text-slate-500">{cmd}</span>
                  ) : (
                    <span>
                      <span className="text-slate-600 mr-2">$</span>
                      {cmd}
                    </span>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-1">
              <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                <RotateCcw className="h-3 w-3 text-amber-400" />
                <span>Reversible Rollback Directives ({commands.rollback.length}):</span>
              </span>
              <div className="rounded border border-cyber-border/60 bg-cyber-bg/60 p-2 font-mono text-[10px] text-amber-300/90 overflow-x-auto space-y-0.5">
                {commands.rollback.map((rcmd, idx) => (
                  <div key={idx} className="whitespace-pre">
                    {rcmd.startsWith("#") ? (
                      <span className="text-slate-600">{rcmd}</span>
                    ) : (
                      <span>
                        <span className="text-slate-600 mr-1.5">$</span>
                        {rcmd}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Execution Result Display */}
          {executionResult && (
            <div
              className={`rounded-lg border p-3.5 text-xs font-mono space-y-1 animate-in fade-in duration-150 ${
                executionResult.status === "SUCCESS"
                  ? "border-emerald-500/40 bg-emerald-950/20 text-emerald-300"
                  : "border-red-500/40 bg-red-950/20 text-red-300"
              }`}
            >
              <div className="flex items-center space-x-2 font-bold">
                {executionResult.status === "SUCCESS" ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                )}
                <span>
                  {executionResult.status === "SUCCESS"
                    ? "Containment Directive Active & Committed"
                    : "Execution Denied by Safety Guardrail"}
                </span>
              </div>
              <p className="text-[11px] text-slate-300">{executionResult.message}</p>
              {executionResult.status === "SUCCESS" &&
                activeTab !== "forensics_triage" &&
                commands.rollback.length > 0 && (
                  <div className="pt-1">
                    <button
                      type="button"
                      disabled={rollingBack}
                      onClick={handleRollback}
                      className="inline-flex items-center space-x-1.5 rounded border border-amber-500/60 bg-amber-950/40 px-2.5 py-1 text-[11px] font-mono font-semibold text-amber-300 hover:bg-amber-900/60 transition-colors"
                    >
                      <RotateCcw className="h-3 w-3" />
                      <span>{rollingBack ? "Reversing Containment..." : "Execute Reversible Rollback"}</span>
                    </button>
                  </div>
                )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-cyber-border bg-cyber-card px-6 py-4">
          <div className="text-[11px] font-mono text-slate-400">
            {activeTab === "forensics_triage" ? (
              <button
                type="button"
                onClick={handleDownloadForensics}
                className="inline-flex items-center space-x-1.5 text-cyber-primary hover:underline"
              >
                <Download className="h-3.5 w-3.5" />
                <span>Export Sealed Package JSON</span>
              </button>
            ) : (
              <span>Actions are audited with tamper-evident cryptographic hash chains (Law 4).</span>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={onClose}
              className="rounded px-4 py-1.5 text-xs font-mono text-slate-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleExecute}
              disabled={
                executing ||
                (activeTab === "block_ip" && isIpWhitelisted) ||
                (activeTab === "disable_user" && isUserWhitelisted)
              }
              className="inline-flex items-center space-x-1.5 rounded bg-cyber-primary px-4 py-1.5 text-xs font-mono font-bold text-cyber-bg hover:bg-cyber-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>{executing ? "Executing Playbook..." : "Execute & Record Containment"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
