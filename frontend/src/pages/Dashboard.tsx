import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ShieldAlert,
  Flame,
  Server,
  Clock,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { alertsApi, incidentsApi, reportsApi } from "../services/api";
import type { Alert, DashboardMetrics, Incident } from "../types";
import { StatCard } from "../components/StatCard";
import {
  AlertStatusBadge,
  IncidentStatusBadge,
  RiskScoreBadge,
  SeverityBadge,
} from "../components/AlertBadge";

export const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const fetchDashboardData = async () => {
    try {
      const [m, a, inc] = await Promise.all([
        reportsApi.getMetrics(),
        alertsApi.getAlerts({ limit: 6 }),
        incidentsApi.getIncidents({ limit: 6 }),
      ]);
      setMetrics(m);
      setRecentAlerts(a);
      setRecentIncidents(inc);
      setLastRefreshed(new Date());
    } catch (err) {
      console.error("Failed to load dashboard telemetry:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    // 5-second polling for real-time SOC operations
    const interval = setInterval(fetchDashboardData, 5000);

    const handleSimComplete = () => {
      fetchDashboardData();
    };
    window.addEventListener("sentinelx:simulation-complete", handleSimComplete);

    return () => {
      clearInterval(interval);
      window.removeEventListener("sentinelx:simulation-complete", handleSimComplete);
    };
  }, []);

  const formatMTTD = (seconds: number | null) => {
    if (seconds === null || seconds === undefined) return "N/A";
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
    return `${seconds.toFixed(2)} s`;
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Live Status */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <span>SOC Operational Command</span>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/20">
              LIVE TELEMETRY
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time pipeline monitoring, MITRE ATT&CK correlation, and autonomous triage
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-400">
            <Clock className="h-3.5 w-3.5 text-slate-500" />
            <span>Refreshed: {lastRefreshed.toLocaleTimeString()}</span>
          </div>
          <button
            onClick={() => {
              setLoading(true);
              fetchDashboardData();
            }}
            className="flex items-center space-x-1 rounded border border-cyber-border bg-cyber-card px-2.5 py-1 text-xs font-mono text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin text-cyber-primary" : ""}`} />
            <span>Poll</span>
          </button>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <StatCard
          title="Telemetry Events"
          value={metrics ? metrics.total_events.toLocaleString() : "--"}
          subtitle="Normalized Ingested Logs"
          icon={Activity}
          variant="default"
        />
        <StatCard
          title="Active Alerts"
          value={metrics ? metrics.active_alerts : "--"}
          subtitle="Deduplicated Rule Matches"
          icon={ShieldAlert}
          variant={metrics && metrics.active_alerts > 0 ? "critical" : "default"}
        />
        <StatCard
          title="Open Incidents"
          value={metrics ? metrics.open_incidents : "--"}
          subtitle="Correlated Kill-Chains"
          icon={Flame}
          variant={metrics && metrics.open_incidents > 0 ? "warning" : "default"}
        />
        <StatCard
          title="Monitored Assets"
          value={metrics ? metrics.monitored_assets : "--"}
          subtitle="CMDB Tracked Targets"
          icon={Server}
          variant="accent"
        />
        <StatCard
          title="Mean Time To Detect"
          value={metrics ? formatMTTD(metrics.mttd_seconds) : "--"}
          subtitle="Detection Pipeline Latency"
          icon={Clock}
          variant="success"
        />
      </div>

      {/* Severity Breakdown Bar */}
      {metrics && metrics.severity_breakdown && (
        <div className="rounded-lg border border-cyber-border bg-cyber-surface p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
              Threat Severity Distribution
            </span>
            <span className="font-mono text-xs text-slate-400">
              Total Alerts: {metrics.active_alerts}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded border border-red-900/60 bg-red-950/20 p-2.5">
              <span className="text-[11px] font-mono text-red-400 uppercase">Critical</span>
              <p className="text-xl font-mono font-bold text-red-300 mt-1">
                {metrics.severity_breakdown.critical || 0}
              </p>
            </div>
            <div className="rounded border border-orange-900/60 bg-orange-950/20 p-2.5">
              <span className="text-[11px] font-mono text-orange-400 uppercase">High</span>
              <p className="text-xl font-mono font-bold text-orange-300 mt-1">
                {metrics.severity_breakdown.high || 0}
              </p>
            </div>
            <div className="rounded border border-amber-900/60 bg-amber-950/20 p-2.5">
              <span className="text-[11px] font-mono text-amber-400 uppercase">Medium</span>
              <p className="text-xl font-mono font-bold text-amber-300 mt-1">
                {metrics.severity_breakdown.medium || 0}
              </p>
            </div>
            <div className="rounded border border-cyan-900/60 bg-cyan-950/20 p-2.5">
              <span className="text-[11px] font-mono text-cyan-400 uppercase">Low</span>
              <p className="text-xl font-mono font-bold text-cyan-300 mt-1">
                {metrics.severity_breakdown.low || 0}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Split View: Live Incidents & Recent Alerts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Active Correlated Incidents */}
        <div className="rounded-lg border border-cyber-border bg-cyber-surface p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-2">
                <Flame className="h-5 w-5 text-orange-400" />
                <h2 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
                  Correlated Incidents
                </h2>
              </div>
              <Link
                to="/incidents"
                className="flex items-center space-x-1 text-xs font-mono text-cyber-primary hover:underline"
              >
                <span>View All</span>
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            <div className="mt-4 space-y-3">
              {recentIncidents.length === 0 ? (
                <p className="py-6 text-center text-xs font-mono text-slate-500">
                  No active incidents detected. All monitored systems calm.
                </p>
              ) : (
                recentIncidents.map((inc) => (
                  <div
                    key={inc.id}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-md border border-cyber-border bg-cyber-card p-3 hover:border-slate-500 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={inc.severity} />
                        <IncidentStatusBadge status={inc.status} />
                        <RiskScoreBadge score={inc.risk_score} />
                      </div>
                      <Link
                        to={`/incidents?selected=${inc.id}`}
                        className="text-sm font-semibold text-slate-100 hover:text-cyber-primary font-mono line-clamp-1"
                      >
                        {inc.title}
                      </Link>
                      <p className="text-[11px] text-slate-400 font-mono">
                        Target: {inc.target_host || "N/A"} | Correlated Alerts: {inc.alert_count}
                      </p>
                    </div>
                    <div className="text-right text-[11px] font-mono text-slate-500 shrink-0">
                      {new Date(inc.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Live Alert Stream */}
        <div className="rounded-lg border border-cyber-border bg-cyber-surface p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="h-5 w-5 text-red-400" />
                <h2 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
                  Recent Alerts Queue
                </h2>
              </div>
              <Link
                to="/alerts"
                className="flex items-center space-x-1 text-xs font-mono text-cyber-primary hover:underline"
              >
                <span>View Queue</span>
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            <div className="mt-4 space-y-3">
              {recentAlerts.length === 0 ? (
                <p className="py-6 text-center text-xs font-mono text-slate-500">
                  No alerts triggered. Zero active signatures matched.
                </p>
              ) : (
                recentAlerts.map((alt) => (
                  <div
                    key={alt.id}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-md border border-cyber-border bg-cyber-card p-3 hover:border-slate-500 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={alt.severity} />
                        <AlertStatusBadge status={alt.status} />
                        {alt.mitre_attack_id && (
                          <span className="text-[10px] font-mono px-1 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            {alt.mitre_attack_id}
                          </span>
                        )}
                      </div>
                      <Link
                        to={`/alerts?selected=${alt.id}`}
                        className="text-sm font-semibold text-slate-100 hover:text-cyber-primary font-mono line-clamp-1 block transition-colors"
                      >
                        {alt.rule_name}
                      </Link>
                      <p className="text-[11px] text-slate-400 font-mono">
                        Src: {alt.source_ip} | Host: {alt.target_host || "N/A"} | Occurrences:{" "}
                        {alt.occurrence_count}
                      </p>
                    </div>
                    <div className="text-right text-[11px] font-mono text-slate-500 shrink-0">
                      {new Date(alt.last_seen).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
