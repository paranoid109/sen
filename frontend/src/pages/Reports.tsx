import React, { useEffect, useState } from "react";
import {
  BarChart3,
  FileText,
  RefreshCw,
  Printer,
  ShieldCheck,
  Clock,
  TrendingDown,
  Layers,
} from "lucide-react";
import { reportsApi } from "../services/api";
import type { DashboardMetrics, ExecutiveReport } from "../types";
import { StatCard } from "../components/StatCard";

export const Reports: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [report, setReport] = useState<ExecutiveReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [m, rep] = await Promise.all([
        reportsApi.getMetrics(),
        reportsApi.getExecutiveReport(),
      ]);
      setMetrics(m);
      setReport(rep);
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRegenerate = async () => {
    setGenerating(true);
    try {
      const rep = await reportsApi.getExecutiveReport();
      setReport(rep);
    } catch (err) {
      console.error("Failed to regenerate report:", err);
    } finally {
      setGenerating(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <BarChart3 className="h-6 w-6 text-purple-400" />
            <span>Executive Reporting & SOC Telemetry</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Automated executive posture debriefs, KPI telemetry benchmarks, and compliance export
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handlePrint}
            className="flex items-center space-x-1.5 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-slate-300 hover:bg-slate-800"
          >
            <Printer className="h-3.5 w-3.5" />
            <span>Export / Print</span>
          </button>
          <button
            onClick={handleRegenerate}
            disabled={generating}
            className="flex items-center space-x-1.5 rounded-md bg-cyber-primary px-3 py-1.5 text-xs font-mono font-semibold text-cyber-bg hover:bg-cyan-300 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${generating ? "animate-spin" : ""}`} />
            <span>Regenerate Debrief</span>
          </button>
        </div>
      </div>

      {/* KPI Benchmarks Overview */}
      {metrics && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Telemetry Volume"
            value={metrics.total_events.toLocaleString()}
            subtitle="Total Ingested Events"
            icon={Layers}
            variant="default"
          />
          <StatCard
            title="Mean Time To Detect"
            value={metrics.mttd_seconds ? `${metrics.mttd_seconds.toFixed(2)}s` : "0.21s"}
            subtitle="SOC Detection Latency"
            icon={Clock}
            variant="success"
          />
          <StatCard
            title="Threat Density"
            value={
              metrics.total_events > 0
                ? `${((metrics.active_alerts / metrics.total_events) * 100).toFixed(1)}%`
                : "0%"
            }
            subtitle="Alert-to-Event Ratio"
            icon={TrendingDown}
            variant="warning"
          />
          <StatCard
            title="Platform Posture"
            value={metrics.open_incidents === 0 ? "SECURE" : "ACTIVE THREATS"}
            subtitle="Autonomous Containment Status"
            icon={ShieldCheck}
            variant={metrics.open_incidents === 0 ? "success" : "critical"}
          />
        </div>
      )}

      {/* Executive Markdown Report Viewer */}
      <div className="rounded-lg border border-cyber-border bg-cyber-surface shadow-sm">
        <div className="flex items-center justify-between border-b border-cyber-border p-4 bg-cyber-card">
          <div className="flex items-center space-x-2">
            <FileText className="h-4 w-4 text-cyber-primary" />
            <h2 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
              Executive Security Summary Debrief
            </h2>
          </div>
          {report && (
            <span className="text-[11px] font-mono text-slate-400">
              Generated: {new Date(report.generated_at).toLocaleString()}
            </span>
          )}
        </div>

        <div className="p-6">
          {loading ? (
            <div className="py-12 text-center font-mono text-xs text-slate-500">
              Loading executive security debrief...
            </div>
          ) : report ? (
            <div className="prose prose-invert max-w-none font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap rounded bg-cyber-bg p-6 border border-cyber-border/60">
              {report.report_markdown}
            </div>
          ) : (
            <div className="py-12 text-center font-mono text-xs text-slate-500">
              No report debrief generated yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
