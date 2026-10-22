import React, { useEffect, useState, useCallback } from "react";
import { useSearchParams, Link } from "react-router-dom";
import {
  Flame,
  Filter,
  Layers,
  RefreshCw,
  Clock,
  Shield,
  Search,
  X,
  ExternalLink,
  Pause,
  Play,
  Terminal,
  Server,
  Send,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { incidentsApi } from "../services/api";
import type { Incident, IncidentDetail, IncidentStatus, Alert } from "../types";
import {
  IncidentStatusBadge,
  RiskScoreBadge,
  SeverityBadge,
} from "../components/AlertBadge";
import { IncidentTimeline } from "../components/IncidentTimeline";
import { EvidenceDrawer } from "../components/EvidenceDrawer";
import { SOARPlaybookModal } from "../components/SOARPlaybookModal";
import { AICopilotModal } from "../components/AICopilotModal";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";

type PollInterval = 5000 | 15000 | 30000 | 0;

export const Incidents: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlSelected = searchParams.get("selected");
  const urlSearch = searchParams.get("search") || "";

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [searchInput, setSearchInput] = useState(urlSearch);
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  // Alert Evidence Drawer inside incident console
  const [drawerAlert, setDrawerAlert] = useState<Alert | null>(null);

  // SOAR Playbook & Containment Modal
  const [isSOARModalOpen, setIsSOARModalOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);

  // Status update
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [updateNotes, setUpdateNotes] = useState("");

  // Polling state
  const [pollInterval, setPollInterval] = useState<PollInterval>(15000);
  const [isPaused, setIsPaused] = useState(false);

  const { hasRole } = useAuth();
  const { showToast } = useToast();
  const canUpdate = hasRole(["Admin", "Analyst"]);

  // Pause if user is typing notes, inspecting evidence, or running SOAR modal
  const isInteracting = Boolean(updateNotes.trim() || drawerAlert || isSOARModalOpen || isPaused);

  const loadIncidentDetail = useCallback(async (id: string, silent = false) => {
    if (!silent) setLoadingDetail(true);
    try {
      const detail = await incidentsApi.getIncident(id);
      setSelectedIncident(detail);
      const newParams = new URLSearchParams(searchParams);
      newParams.set("selected", id);
      setSearchParams(newParams);
    } catch (err) {
      console.error("Failed to load incident detail:", err);
      showToast("Failed to load incident details", "error");
    } finally {
      if (!silent) setLoadingDetail(false);
    }
  }, [searchParams, setSearchParams, showToast]);

  const fetchIncidents = useCallback(async (silent = false) => {
    if (!silent) setLoadingList(true);
    try {
      const params: { status?: string; severity?: string; search?: string } = {};
      if (statusFilter !== "ALL") params.status = statusFilter;
      if (severityFilter !== "ALL") params.severity = severityFilter;
      if (searchInput.trim()) params.search = searchInput.trim();

      const data = await incidentsApi.getIncidents(params);
      setIncidents(data);

      const targetId = urlSelected || (data.length > 0 ? data[0].id : null);
      if (targetId) {
        loadIncidentDetail(targetId, silent);
      } else {
        setSelectedIncident(null);
      }
    } catch (err) {
      console.error("Failed to load incidents:", err);
      showToast("Failed to fetch incidents", "error");
    } finally {
      if (!silent) setLoadingList(false);
    }
  }, [statusFilter, severityFilter, searchInput, urlSelected, loadIncidentDetail, showToast]);

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter, severityFilter, searchInput, fetchIncidents]);

  // Auto-refresh interval & simulation event listener
  useEffect(() => {
    const handleSimComplete = () => {
      fetchIncidents(true);
    };
    window.addEventListener("sentinelx:simulation-complete", handleSimComplete);

    if (pollInterval === 0 || isInteracting) {
      return () => {
        window.removeEventListener("sentinelx:simulation-complete", handleSimComplete);
      };
    }

    const timer = setInterval(() => {
      fetchIncidents(true);
    }, pollInterval);

    return () => {
      clearInterval(timer);
      window.removeEventListener("sentinelx:simulation-complete", handleSimComplete);
    };
  }, [pollInterval, isInteracting, fetchIncidents]);

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

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!selectedIncident) return;
    setUpdatingStatus(true);
    try {
      const updated = await incidentsApi.updateIncident(selectedIncident.id, {
        status: newStatus,
        notes: updateNotes.trim() || undefined,
      });
      setSelectedIncident(updated);
      setUpdateNotes("");
      setIncidents((prev) =>
        prev.map((i) =>
          i.id === updated.id
            ? { ...i, status: updated.status, risk_score: updated.risk_score }
            : i
        )
      );
      showToast(`Incident status updated to ${newStatus}`, "success");
    } catch (err: any) {
      const msg = err.response?.data?.detail || "Failed to update incident status.";
      showToast(msg, "error");
    } finally {
      setUpdatingStatus(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Flame className="h-6 w-6 text-orange-400" />
            <span>Incident Correlation & Response</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300 border border-slate-700">
              {incidents.length} Correlated Cases
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Cross-event kill-chain correlation, bounded risk scoring [0, 100], and audit timeline
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
            onClick={() => fetchIncidents(false)}
            className="flex items-center space-x-1.5 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loadingList ? "animate-spin text-cyber-primary" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <form onSubmit={handleSearchSubmit} className="relative flex-1 min-w-[260px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search by title, target host, or description..."
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

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center space-x-2 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-xs font-mono text-slate-200 focus:outline-none"
            >
              <option value="ALL" className="bg-cyber-surface text-slate-200">All Statuses</option>
              <option value="OPEN" className="bg-cyber-surface text-slate-200">OPEN</option>
              <option value="INVESTIGATING" className="bg-cyber-surface text-slate-200">INVESTIGATING</option>
              <option value="RESOLVED" className="bg-cyber-surface text-slate-200">RESOLVED</option>
              <option value="CLOSED" className="bg-cyber-surface text-slate-200">CLOSED</option>
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

      {/* Two-Column Master-Detail Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Incidents List (5 cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="rounded-lg border border-cyber-border bg-cyber-surface p-3">
            <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-400">
              Correlated Cases
            </h2>
          </div>

          <div className="space-y-2.5 max-h-[750px] overflow-y-auto pr-1">
            {incidents.length === 0 ? (
              <div className="rounded-lg border border-cyber-border bg-cyber-surface p-6 text-center text-xs font-mono text-slate-500">
                {loadingList ? "Loading incidents..." : "No incidents matching filter criteria."}
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id;
                return (
                  <div
                    key={inc.id}
                    onClick={() => loadIncidentDetail(inc.id)}
                    className={`cursor-pointer rounded-lg border p-4 transition-all ${
                      isSelected
                        ? "border-cyber-primary bg-cyber-card shadow-md"
                        : "border-cyber-border bg-cyber-surface hover:border-slate-500 hover:bg-cyber-card/50"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={inc.severity} />
                        <IncidentStatusBadge status={inc.status} />
                      </div>
                      <RiskScoreBadge score={inc.risk_score} />
                    </div>

                    <h3 className="mt-2 text-sm font-semibold font-mono text-white line-clamp-2">
                      {inc.title}
                    </h3>

                    <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>Target: {inc.target_host || "Unassigned"}</span>
                      <span>{inc.alert_count} Alerts</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Incident Investigation Detail Console (7 cols) */}
        <div className="lg:col-span-7">
          {loadingDetail ? (
            <div className="flex h-96 items-center justify-center rounded-lg border border-cyber-border bg-cyber-surface font-mono text-xs text-slate-400">
              <RefreshCw className="h-5 w-5 animate-spin text-cyber-primary mr-2" />
              Loading incident investigation dossier...
            </div>
          ) : selectedIncident ? (
            <div className="space-y-6 rounded-lg border border-cyber-border bg-cyber-surface p-6 shadow-sm">
              {/* Incident Header */}
              <div className="border-b border-cyber-border pb-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center space-x-2">
                    <SeverityBadge severity={selectedIncident.severity} />
                    <IncidentStatusBadge status={selectedIncident.status} />
                    <RiskScoreBadge score={selectedIncident.risk_score} />
                  </div>
                  <span className="text-xs font-mono text-slate-500">
                    ID: {selectedIncident.id}
                  </span>
                </div>

                <h2 className="text-lg font-bold font-mono text-white">
                  {selectedIncident.title}
                </h2>

                {selectedIncident.description && (
                  <p className="text-xs text-slate-300 font-sans leading-relaxed bg-cyber-card border border-cyber-border/70 rounded p-3">
                    {selectedIncident.description}
                  </p>
                )}

                <div className="grid grid-cols-2 gap-3 text-xs font-mono text-slate-400 pt-1">
                  <div>
                    <span className="text-slate-500">Target Host:</span>{" "}
                    <span className="text-slate-200 font-semibold">{selectedIncident.target_host || "N/A"}</span>
                    {selectedIncident.target_host && (
                      <Link
                        to={`/assets?search=${selectedIncident.target_host}`}
                        className="ml-2 text-cyber-primary hover:underline inline-flex items-center text-[11px]"
                      >
                        <Server className="h-3 w-3 mr-0.5" />
                        <span>Asset CMDB</span>
                      </Link>
                    )}
                  </div>
                  <div>
                    <span className="text-slate-500">Created:</span>{" "}
                    <span className="text-slate-200">
                      {new Date(selectedIncident.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Lifecycle State Controls with Notes */}
              {canUpdate && (
                <div className="rounded-lg border border-cyber-border bg-cyber-card p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-1.5">
                      <Send className="h-3.5 w-3.5 text-cyber-primary" />
                      <span>Incident Response & Containment</span>
                    </h3>
                    <div className="flex items-center space-x-2">
                      <button
                        type="button"
                        onClick={() => setIsCopilotOpen(true)}
                        className="inline-flex items-center space-x-1.5 rounded border border-cyber-primary/40 bg-cyber-primary/10 px-2.5 py-1 text-xs font-mono font-bold text-cyber-primary hover:bg-cyber-primary/20 transition-all shadow-sm"
                        title="Open AI SOC Copilot for instant briefing and triage advice"
                      >
                        <Sparkles className="h-3.5 w-3.5" />
                        <span>Ask AI Copilot</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setIsSOARModalOpen(true)}
                        className="inline-flex items-center space-x-1.5 rounded border border-cyber-primary/70 bg-cyber-primary/10 px-2.5 py-1 text-xs font-mono font-bold text-cyber-primary hover:bg-cyber-primary/20 transition-all shadow-sm"
                      >
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>SOAR Playbook & Forensics</span>
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {(["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"] as IncidentStatus[]).map(
                      (st) => (
                        <button
                          key={st}
                          disabled={updatingStatus || selectedIncident.status === st}
                          onClick={() => handleStatusChange(st)}
                          className={`rounded px-3 py-1.5 text-xs font-mono font-medium transition-all ${
                            selectedIncident.status === st
                              ? "bg-cyber-primary text-cyber-bg font-bold cursor-default shadow-sm"
                              : "border border-cyber-border bg-cyber-surface text-slate-300 hover:border-cyber-primary hover:text-white"
                          }`}
                        >
                          Mark {st}
                        </button>
                      )
                    )}
                  </div>

                  <div>
                    <input
                      type="text"
                      value={updateNotes}
                      onChange={(e) => setUpdateNotes(e.target.value)}
                      placeholder="Optional analyst containment notes (e.g. Quarantined infected server subnet)..."
                      className="w-full rounded border border-cyber-border bg-cyber-bg px-3 py-1.5 text-xs font-mono text-white placeholder-slate-600 focus:border-cyber-primary focus:outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Correlated Alerts List */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-cyber-primary" />
                    <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Correlated Threat Signatures ({selectedIncident.alerts.length})
                    </h3>
                  </div>
                  <Link
                    to={`/alerts?search=${selectedIncident.target_host || ""}`}
                    className="text-[11px] font-mono text-cyber-primary hover:underline flex items-center space-x-1"
                  >
                    <span>Inspect in Alerts Queue</span>
                    <ExternalLink className="h-3 w-3" />
                  </Link>
                </div>

                <div className="space-y-2">
                  {selectedIncident.alerts.map((alt) => (
                    <div
                      key={alt.id}
                      onClick={() => setDrawerAlert(alt)}
                      className="rounded border border-cyber-border bg-cyber-card p-3 text-xs font-mono space-y-1 hover:border-slate-500 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-white hover:text-cyber-primary">{alt.rule_name}</span>
                        <div className="flex items-center space-x-2">
                          <SeverityBadge severity={alt.severity} />
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setDrawerAlert(alt);
                            }}
                            className="text-slate-400 hover:text-cyber-primary p-0.5"
                            title="Inspect Evidence"
                          >
                            <Terminal className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-slate-400 text-[11px]">
                        <span>Source IP: {alt.source_ip}</span>
                        <span>Occurrences: {alt.occurrence_count}x</span>
                        <span>{new Date(alt.last_seen).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Chronological Incident Timeline */}
              <div className="space-y-3 pt-2">
                <div className="flex items-center space-x-2">
                  <Clock className="h-4 w-4 text-cyber-primary" />
                  <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Incident Audit Timeline
                  </h3>
                </div>

                <IncidentTimeline items={selectedIncident.timeline} />
              </div>
            </div>
          ) : (
            <div className="flex h-96 items-center justify-center rounded-lg border border-cyber-border bg-cyber-surface font-mono text-xs text-slate-500">
              Select an incident from the list to view correlated kill-chains and timeline.
            </div>
          )}
        </div>
      </div>

      {/* Slide-over Evidence Drawer for correlated alerts */}
      <EvidenceDrawer
        alert={drawerAlert}
        onClose={() => setDrawerAlert(null)}
        correlatedIncidentId={selectedIncident?.id}
        onTriageSuccess={() => {
          if (selectedIncident) {
            loadIncidentDetail(selectedIncident.id, true);
          }
        }}
      />

      {/* SOAR Playbook & Digital Forensics Modal */}
      <SOARPlaybookModal
        incident={selectedIncident}
        isOpen={isSOARModalOpen}
        onClose={() => setIsSOARModalOpen(false)}
        onActionExecuted={() => {
          if (selectedIncident) {
            loadIncidentDetail(selectedIncident.id, true);
          }
        }}
      />

      {/* AI SOC Analyst Copilot Modal */}
      <AICopilotModal
        incident={selectedIncident}
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
      />
    </div>
  );
};
