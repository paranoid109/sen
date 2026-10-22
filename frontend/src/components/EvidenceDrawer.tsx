import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  X,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Flame,
  Terminal,
  Send,
} from "lucide-react";
import type { Alert, AlertStatus } from "../types";
import { AlertStatusBadge, SeverityBadge } from "./AlertBadge";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { alertsApi, type AlertEvidenceEvent } from "../services/api";

interface EvidenceDrawerProps {
  alert: Alert | null;
  onClose: () => void;
  onTriageSuccess?: (updated: Alert) => void;
  correlatedIncidentId?: string | null;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({
  alert,
  onClose,
  onTriageSuccess,
  correlatedIncidentId,
}) => {
  const { hasRole } = useAuth();
  const { showToast } = useToast();
  const canTriage = hasRole(["Admin", "Analyst"]);

  const [copied, setCopied] = useState(false);
  const [triageStatus, setTriageStatus] = useState<AlertStatus>("INVESTIGATING");
  const [triageNotes, setTriageNotes] = useState("");
  const [submittingTriage, setSubmittingTriage] = useState(false);
  const [hydratedEvents, setHydratedEvents] = useState<AlertEvidenceEvent[]>([]);

  useEffect(() => {
    if (!alert) {
      setHydratedEvents([]);
      return;
    }
    let active = true;
    alertsApi
      .getAlertEvents(alert.id)
      .then((events) => {
        if (active && Array.isArray(events)) {
          setHydratedEvents(events);
        }
      })
      .catch(() => {
        // Fallback to alert.evidence lines in offline/unit-test environments
        if (active) setHydratedEvents([]);
      });
    return () => {
      active = false;
    };
  }, [alert]);

  if (!alert) return null;

  const formattedEvidenceLines =
    hydratedEvents.length > 0
      ? hydratedEvents.map(
          (ev) =>
            `[${new Date(ev.event_time).toISOString()}] (${ev.event_type}) ${
              ev.raw_payload || JSON.stringify(ev.details)
            }`
        )
      : alert.evidence;

  const handleCopyEvidence = () => {
    const text = formattedEvidenceLines.join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    showToast("Evidence copied to clipboard", "info", 2000);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleTriageSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittingTriage(true);
    try {
      const updated = await alertsApi.triageAlert(alert.id, {
        status: triageStatus,
        notes: triageNotes || undefined,
      });
      showToast(`Alert triaged to ${triageStatus}`, "success");
      if (onTriageSuccess) {
        onTriageSuccess(updated);
      }
      onClose();
    } catch (err: any) {
      showToast(err.response?.data?.detail || "Failed to update alert triage status.", "error");
    } finally {
      setSubmittingTriage(false);
    }
  };

  // Convert T1110.001 to https://attack.mitre.org/techniques/T1110/001/
  const formatMitreUrl = (attackId: string) => {
    const formatted = attackId.replace(".", "/");
    return `https://attack.mitre.org/techniques/${formatted}/`;
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="absolute inset-y-0 right-0 flex max-w-full pl-10">
        <div className="w-screen max-w-2xl border-l border-cyber-border bg-cyber-surface p-6 shadow-2xl flex flex-col justify-between overflow-y-auto">
          {/* Header */}
          <div>
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <div className="flex items-center space-x-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyber-primary/10 border border-cyber-primary/30">
                  <ShieldAlert className="h-5 w-5 text-cyber-primary" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs text-slate-400 font-semibold">{alert.rule_id}</span>
                    <SeverityBadge severity={alert.severity} />
                    <AlertStatusBadge status={alert.status} />
                  </div>
                  <h2 className="font-mono text-base font-bold text-white mt-1">
                    {alert.rule_name}
                  </h2>
                </div>
              </div>
              <button
                onClick={onClose}
                className="rounded-md border border-cyber-border p-1.5 text-slate-400 hover:bg-cyber-card hover:text-white transition-colors"
                title="Close drawer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Entity Metadata Grid */}
            <div className="mt-5 grid grid-cols-2 gap-3 font-mono text-xs">
              <div className="rounded-md border border-cyber-border bg-cyber-card p-3">
                <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Source Attacker IP</span>
                <span className="text-white font-semibold text-sm mt-0.5 block">{alert.source_ip}</span>
              </div>
              <div className="rounded-md border border-cyber-border bg-cyber-card p-3">
                <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Target Host</span>
                <div className="flex items-center justify-between mt-0.5">
                  <span className="text-white font-semibold text-sm">{alert.target_host || "Unassigned"}</span>
                  {alert.target_host && (
                    <Link
                      to={`/assets?search=${alert.target_host}`}
                      className="text-[11px] text-cyber-primary hover:underline flex items-center space-x-0.5"
                    >
                      <span>CMDB</span>
                      <ExternalLink className="h-3 w-3" />
                    </Link>
                  )}
                </div>
              </div>
              <div className="rounded-md border border-cyber-border bg-cyber-card p-3">
                <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Occurrences</span>
                <span className="text-emerald-400 font-semibold text-sm mt-0.5 block">
                  {alert.occurrence_count} events aggregated
                </span>
              </div>
              <div className="rounded-md border border-cyber-border bg-cyber-card p-3">
                <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Time Range</span>
                <span className="text-slate-300 text-[11px] mt-0.5 block">
                  {new Date(alert.first_seen).toLocaleTimeString()} &rarr; {new Date(alert.last_seen).toLocaleTimeString()}
                </span>
              </div>
            </div>

            {/* MITRE ATT&CK & Correlated Incident Banner */}
            <div className="mt-4 flex flex-wrap gap-2">
              {alert.mitre_attack_id && (
                <a
                  href={formatMitreUrl(alert.mitre_attack_id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center space-x-1.5 rounded border border-amber-800/60 bg-amber-950/40 px-2.5 py-1 text-xs font-mono text-amber-300 hover:bg-amber-950/70 transition-colors"
                >
                  <span>MITRE {alert.mitre_attack_id}</span>
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}

              {correlatedIncidentId ? (
                <Link
                  to={`/incidents?selected=${correlatedIncidentId}`}
                  className="inline-flex items-center space-x-1.5 rounded border border-red-800/60 bg-red-950/40 px-2.5 py-1 text-xs font-mono text-red-300 hover:bg-red-950/70 transition-colors"
                >
                  <Flame className="h-3 w-3 text-red-400" />
                  <span>View Correlated Incident</span>
                </Link>
              ) : (
                <span className="inline-flex items-center space-x-1 rounded border border-slate-700 bg-slate-800/50 px-2.5 py-1 text-xs font-mono text-slate-400">
                  <span>Deduplicated Alert Record</span>
                </span>
              )}
            </div>

            {/* Raw Evidence Viewer */}
            <div className="mt-6">
              <div className="flex items-center justify-between pb-2">
                <div className="flex items-center space-x-2 text-xs font-mono text-slate-300 font-semibold">
                  <Terminal className="h-4 w-4 text-cyber-primary" />
                  <span>Raw Forensic Evidence ({alert.evidence.length} samples)</span>
                </div>
                <button
                  onClick={handleCopyEvidence}
                  className="flex items-center space-x-1 rounded border border-cyber-border bg-cyber-card px-2 py-0.5 text-[11px] font-mono text-slate-300 hover:bg-slate-800 transition-colors"
                >
                  {copied ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      <span>Copy Log</span>
                    </>
                  )}
                </button>
              </div>

              <div className="rounded-md border border-cyber-border bg-black/80 p-3 font-mono text-xs overflow-x-auto max-h-60 text-slate-300 space-y-1">
                {formattedEvidenceLines.map((line, idx) => (
                  <div key={idx} className="flex items-start space-x-2 border-b border-slate-900 pb-1 last:border-0 last:pb-0">
                    <span className="text-slate-600 select-none text-[11px] w-6 shrink-0 text-right">
                      {idx + 1}
                    </span>
                    <span className="break-all text-emerald-300/90 font-mono text-[11px] leading-relaxed">
                      {line}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Triage Action Section */}
          {canTriage && (
            <div className="mt-6 border-t border-cyber-border pt-4">
              <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center space-x-1.5">
                <Send className="h-3.5 w-3.5 text-cyber-primary" />
                <span>Analyst Triage Action</span>
              </h3>
              <form onSubmit={handleTriageSubmit} className="space-y-3">
                <div className="grid grid-cols-3 gap-2">
                  {(["INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"] as AlertStatus[]).map((st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => setTriageStatus(st)}
                      className={`rounded border px-2.5 py-1.5 text-xs font-mono font-medium transition-all ${
                        triageStatus === st
                          ? "border-cyber-primary bg-cyber-primary/20 text-cyber-primary font-bold shadow-sm"
                          : "border-cyber-border bg-cyber-card text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>

                <div>
                  <textarea
                    rows={2}
                    value={triageNotes}
                    onChange={(e) => setTriageNotes(e.target.value)}
                    placeholder="Enter analyst investigation notes (e.g. Verified harmless scanner, host quarantined)..."
                    className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-2 text-xs font-mono text-white placeholder-slate-600 focus:border-cyber-primary focus:outline-none focus:ring-1 focus:ring-cyber-primary"
                  />
                </div>

                <div className="flex justify-end space-x-2">
                  <button
                    type="button"
                    onClick={onClose}
                    className="rounded border border-cyber-border px-3 py-1.5 text-xs font-mono text-slate-400 hover:bg-cyber-card"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submittingTriage}
                    className="flex items-center space-x-1.5 rounded border border-cyber-primary/40 bg-cyber-primary/20 px-4 py-1.5 text-xs font-mono font-medium text-cyber-primary hover:bg-cyber-primary/30 disabled:opacity-50"
                  >
                    {submittingTriage ? "Updating..." : "Commit Triage"}
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
