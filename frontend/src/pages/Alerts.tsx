import React, { useEffect, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ShieldAlert,
  Filter,
  Search,
  X,
  Eye,
  RefreshCw,
  Layers,
  Pause,
  Play,
  Terminal,
} from "lucide-react";
import { alertsApi } from "../services/api";
import type { Alert, AlertStatus } from "../types";
import { AlertStatusBadge, SeverityBadge } from "../components/AlertBadge";
import { EvidenceDrawer } from "../components/EvidenceDrawer";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";

type PollInterval = 5000 | 15000 | 30000 | 0;

export const Alerts: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlSearch = searchParams.get("search") || "";
  const urlSelected = searchParams.get("selected");

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(urlSearch);
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  // Evidence Drawer & Triage state
  const [drawerAlert, setDrawerAlert] = useState<Alert | null>(null);
  const [selectedAlertForModal, setSelectedAlertForModal] = useState<Alert | null>(null);
  const [triageStatus, setTriageStatus] = useState<AlertStatus>("INVESTIGATING");
  const [triageNotes, setTriageNotes] = useState<string>("");
  const [submittingTriage, setSubmittingTriage] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Polling state
  const [pollInterval, setPollInterval] = useState<PollInterval>(15000);
  const [isPaused, setIsPaused] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const { hasRole } = useAuth();
  const { showToast } = useToast();
  const canTriage = hasRole(["Admin", "Analyst"]);

  // Pause polling if user is actively triaging or inspecting
  const isInteracting = Boolean(selectedAlertForModal || drawerAlert || isPaused);

  const fetchAlerts = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const params: { status?: string; severity?: string; search?: string } = {};
      if (statusFilter !== "ALL") params.status = statusFilter;
      if (severityFilter !== "ALL") params.severity = severityFilter;
      if (searchInput.trim()) params.search = searchInput.trim();

      const data = await alertsApi.getAlerts(params);
      setAlerts(data);
      setLastRefreshed(new Date());

      // If URL has a selected alert ID, open the drawer for it
      if (urlSelected) {
        const found = data.find((a) => a.id === urlSelected);
        if (found) {
          setDrawerAlert(found);
        }
      }
    } catch (err) {
      console.error("Failed to load alerts:", err);
      showToast("Failed to fetch alerts queue", "error");
    } finally {
      if (!silent) setLoading(false);
    }
  }, [statusFilter, severityFilter, searchInput, urlSelected, showToast]);

  // Initial fetch and on filter changes
  useEffect(() => {
    fetchAlerts();
  }, [statusFilter, severityFilter, searchInput, fetchAlerts]);

  // Auto-refresh timer & simulation event listener
  useEffect(() => {
    const handleSimComplete = () => {
      fetchAlerts(true);
    };
    window.addEventListener("sentinelx:simulation-complete", handleSimComplete);

    if (pollInterval === 0 || isInteracting) {
      return () => {
        window.removeEventListener("sentinelx:simulation-complete", handleSimComplete);
      };
    }

    const timer = setInterval(() => {
      fetchAlerts(true);
    }, pollInterval);

    return () => {
      clearInterval(timer);
      window.removeEventListener("sentinelx:simulation-complete", handleSimComplete);
    };
  }, [pollInterval, isInteracting, fetchAlerts]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const newParams = new URLSearchParams(searchParams);
    if (searchInput.trim()) {
      newParams.set("search", searchInput.trim());
    } else {
      newParams.delete("search");
    }
    setSearchParams(newParams);
  };

  const handleClearSearch = () => {
    setSearchInput("");
    const newParams = new URLSearchParams(searchParams);
    newParams.delete("search");
    setSearchParams(newParams);
  };

  const handleOpenDrawer = (alert: Alert) => {
    setDrawerAlert(alert);
    const newParams = new URLSearchParams(searchParams);
    newParams.set("selected", alert.id);
    setSearchParams(newParams);
  };

  const handleCloseDrawer = () => {
    setDrawerAlert(null);
    const newParams = new URLSearchParams(searchParams);
    newParams.delete("selected");
    setSearchParams(newParams);
  };

  const handleOpenTriageModal = (alert: Alert, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedAlertForModal(alert);
    setTriageStatus(alert.status === "NEW" ? "INVESTIGATING" : alert.status);
    setTriageNotes("");
    setActionError(null);
  };

  const handleTriageSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlertForModal) return;
    setSubmittingTriage(true);
    setActionError(null);

    try {
      const updated = await alertsApi.triageAlert(selectedAlertForModal.id, {
        status: triageStatus,
        notes: triageNotes || undefined,
      });

      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      if (drawerAlert?.id === updated.id) {
        setDrawerAlert(updated);
      }
      showToast(`Alert triage status updated to ${triageStatus}`, "success");
      setSelectedAlertForModal(null);
    } catch (err: any) {
      const msg = err.response?.data?.detail || "Failed to update alert triage status.";
      setActionError(msg);
      showToast(msg, "error");
    } finally {
      setSubmittingTriage(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Operational Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <ShieldAlert className="h-6 w-6 text-red-400" />
            <span>Curated Alert Queue</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300 border border-slate-700">
              {alerts.length} Records
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Deduplicated threat signatures, MITRE ATT&CK mappings, and evidence aggregation
          </p>
        </div>

        {/* Live Auto-Refresh & Pulse Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center space-x-1 rounded-md border border-cyber-border bg-cyber-card px-2 py-1 text-xs font-mono text-slate-400">
            <span
              className={`h-2 w-2 rounded-full ${
                isInteracting
                  ? "bg-amber-400"
                  : pollInterval > 0
                  ? "bg-emerald-400 animate-pulse"
                  : "bg-slate-600"
              }`}
            />
            <span>{isInteracting ? "Paused" : pollInterval > 0 ? `Live (${pollInterval / 1000}s)` : "Off"}</span>
          </div>

          <div className="flex items-center space-x-1 rounded-md border border-cyber-border bg-cyber-card p-0.5 text-xs font-mono">
            {[5000, 15000, 30000, 0].map((int) => (
              <button
                key={int}
                onClick={() => {
                  setPollInterval(int as PollInterval);
                  setIsPaused(int === 0);
                }}
                className={`px-2 py-1 rounded transition-colors ${
                  pollInterval === int && !isPaused
                    ? "bg-cyber-primary/20 text-cyber-primary font-bold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {int === 0 ? "Off" : `${int / 1000}s`}
              </button>
            ))}
            <button
              onClick={() => setIsPaused((prev) => !prev)}
              className={`p-1 rounded text-slate-400 hover:text-white transition-colors ${
                isPaused ? "text-amber-400 font-bold" : ""
              }`}
              title={isPaused ? "Resume auto-refresh" : "Pause auto-refresh"}
            >
              {isPaused ? <Play className="h-3 w-3 text-emerald-400" /> : <Pause className="h-3 w-3" />}
            </button>
          </div>

          <button
            onClick={() => fetchAlerts(false)}
            className="flex items-center space-x-1.5 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyber-primary" : ""}`} />
            <span>Refresh</span>
          </button>
          <span className="text-[11px] font-mono text-slate-500 hidden sm:inline" title="Last telemetry fetch">
            {lastRefreshed.toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Search Input */}
        <form onSubmit={handleSearchSubmit} className="relative flex-1 min-w-[260px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search by IP, hostname, rule ID, or MITRE..."
            className="w-full rounded-md border border-cyber-border bg-cyber-card pl-9 pr-8 py-1.5 text-xs font-mono text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none focus:ring-1 focus:ring-cyber-primary"
          />
          {searchInput && (
            <button
              type="button"
              onClick={handleClearSearch}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </form>

        {/* Status and Severity Dropdowns */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center space-x-2 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-xs font-mono text-slate-200 focus:outline-none"
            >
              <option value="ALL" className="bg-cyber-surface text-slate-200">All Statuses</option>
              <option value="NEW" className="bg-cyber-surface text-slate-200">NEW</option>
              <option value="INVESTIGATING" className="bg-cyber-surface text-slate-200">INVESTIGATING</option>
              <option value="RESOLVED" className="bg-cyber-surface text-slate-200">RESOLVED</option>
              <option value="FALSE_POSITIVE" className="bg-cyber-surface text-slate-200">FALSE_POSITIVE</option>
            </select>
          </div>

          <div className="flex items-center space-x-2 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5">
            <Layers className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs font-mono text-slate-200 focus:outline-none"
            >
              <option value="ALL" className="bg-cyber-surface text-slate-200">All Severities</option>
              <option value="critical" className="bg-cyber-surface text-slate-200">Critical</option>
              <option value="high" className="bg-cyber-surface text-slate-200">High</option>
              <option value="medium" className="bg-cyber-surface text-slate-200">Medium</option>
              <option value="low" className="bg-cyber-surface text-slate-200">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="overflow-hidden rounded-lg border border-cyber-border bg-cyber-surface shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-cyber-border text-left font-mono">
            <thead className="bg-cyber-card text-[11px] uppercase tracking-wider text-slate-400">
              <tr>
                <th scope="col" className="px-4 py-3">Severity & Status</th>
                <th scope="col" className="px-4 py-3">Rule & MITRE Technique</th>
                <th scope="col" className="px-4 py-3">Source & Target</th>
                <th scope="col" className="px-4 py-3">Occurrences</th>
                <th scope="col" className="px-4 py-3">Last Seen</th>
                <th scope="col" className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/60 text-xs">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                    {loading ? "Loading alerts..." : "No alerts match the selected criteria."}
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => handleOpenDrawer(alert)}
                    className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={alert.severity} />
                        <AlertStatusBadge status={alert.status} />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-semibold text-slate-200 hover:text-cyber-primary transition-colors">
                        {alert.rule_name}
                      </div>
                      <div className="flex items-center space-x-2 text-[11px] text-slate-400 mt-0.5">
                        <span className="text-cyber-primary">{alert.rule_id}</span>
                        {alert.mitre_attack_id && (
                          <span className="rounded bg-slate-800 px-1 py-0.2 border border-slate-700 text-slate-300">
                            {alert.mitre_attack_id}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="text-slate-200">Src: {alert.source_ip}</div>
                      <div className="text-[11px] text-slate-400">
                        Host: {alert.target_host || "Unassigned"}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="inline-flex items-center px-2 py-0.5 rounded bg-cyber-card border border-cyber-border text-slate-200 font-semibold">
                        {alert.occurrence_count}x
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-slate-400 text-[11px]">
                      {new Date(alert.last_seen).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right space-x-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenDrawer(alert);
                        }}
                        className="inline-flex items-center space-x-1 rounded border border-cyber-border bg-cyber-card px-2 py-1 text-xs text-slate-300 hover:border-cyan-400 hover:text-cyan-400 transition-colors"
                        title="Inspect raw evidence & details"
                      >
                        <Terminal className="h-3 w-3" />
                        <span>Evidence</span>
                      </button>
                      {canTriage && (
                        <button
                          onClick={(e) => handleOpenTriageModal(alert, e)}
                          className="inline-flex items-center space-x-1 rounded border border-cyber-border bg-cyber-card px-2 py-1 text-xs text-slate-300 hover:border-cyber-primary hover:text-cyber-primary transition-colors"
                          title="Triage alert status"
                        >
                          <Eye className="h-3 w-3" />
                          <span>Triage</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-Over Evidence Drawer */}
      <EvidenceDrawer
        alert={drawerAlert}
        onClose={handleCloseDrawer}
        onTriageSuccess={(updated) => {
          setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
        }}
      />

      {/* Triage Modal */}
      {selectedAlertForModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-cyber-border bg-cyber-surface p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div>
                <h3 className="font-mono text-base font-bold text-white">Alert Triage Console</h3>
                <p className="text-xs font-mono text-slate-400">ID: {selectedAlertForModal.id}</p>
              </div>
              <button
                onClick={() => setSelectedAlertForModal(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="rounded-lg border border-cyber-border bg-cyber-card p-3 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Rule:</span>
                <span className="text-slate-200 font-semibold">{selectedAlertForModal.rule_name}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Severity:</span>
                <SeverityBadge severity={selectedAlertForModal.severity} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Source IP:</span>
                <span className="text-slate-200">{selectedAlertForModal.source_ip}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Evidence Count:</span>
                <span className="text-slate-300">{selectedAlertForModal.evidence.length} Events Bound</span>
              </div>
            </div>

            {actionError && (
              <div className="rounded border border-red-800 bg-red-950/40 p-2.5 text-xs text-red-300 font-mono">
                {actionError}
              </div>
            )}

            <form onSubmit={handleTriageSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-1">
                  Target Status Transition
                </label>
                <select
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value as AlertStatus)}
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-xs text-white focus:border-cyber-primary focus:outline-none font-mono"
                >
                  <option value="NEW">NEW</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-1">
                  Investigation & Triage Notes
                </label>
                <textarea
                  rows={3}
                  value={triageNotes}
                  onChange={(e) => setTriageNotes(e.target.value)}
                  placeholder="e.g. Verified legitimate penetration testing traffic from security subnet."
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-xs text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none font-mono"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setSelectedAlertForModal(null)}
                  className="rounded-md border border-cyber-border bg-cyber-card px-4 py-2 text-xs font-mono text-slate-300 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingTriage}
                  className="rounded-md bg-cyber-primary px-4 py-2 text-xs font-mono font-semibold text-cyber-bg hover:bg-cyan-300 disabled:opacity-50"
                >
                  {submittingTriage ? "Recording Mutation..." : "Commit Triage State"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
