import React from "react";
import type { AlertStatus, IncidentStatus, SeverityLevel } from "../types";

export const SeverityBadge: React.FC<{ severity: SeverityLevel | string }> = ({ severity }) => {
  const norm = severity.toLowerCase();
  let colorClasses = "bg-slate-700 text-slate-300 border-slate-600";

  if (norm === "critical") {
    colorClasses = "bg-red-950/80 text-red-300 border-red-800 animate-pulse";
  } else if (norm === "high") {
    colorClasses = "bg-orange-950/80 text-orange-300 border-orange-800";
  } else if (norm === "medium") {
    colorClasses = "bg-amber-950/80 text-amber-300 border-amber-800";
  } else if (norm === "low") {
    colorClasses = "bg-cyan-950/80 text-cyan-300 border-cyan-800";
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border uppercase tracking-wider ${colorClasses}`}
    >
      {severity}
    </span>
  );
};

export const AlertStatusBadge: React.FC<{ status: AlertStatus | string }> = ({ status }) => {
  let colorClasses = "bg-slate-800 text-slate-300 border-slate-700";

  if (status === "NEW") {
    colorClasses = "bg-indigo-950/80 text-indigo-300 border-indigo-700";
  } else if (status === "INVESTIGATING") {
    colorClasses = "bg-amber-950/80 text-amber-300 border-amber-700";
  } else if (status === "RESOLVED") {
    colorClasses = "bg-emerald-950/80 text-emerald-300 border-emerald-700";
  } else if (status === "FALSE_POSITIVE") {
    colorClasses = "bg-zinc-800/80 text-zinc-400 border-zinc-700";
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border tracking-wider ${colorClasses}`}
    >
      {status}
    </span>
  );
};

export const IncidentStatusBadge: React.FC<{ status: IncidentStatus | string }> = ({ status }) => {
  let colorClasses = "bg-slate-800 text-slate-300 border-slate-700";

  if (status === "OPEN") {
    colorClasses = "bg-red-950/80 text-red-300 border-red-700 font-semibold";
  } else if (status === "INVESTIGATING") {
    colorClasses = "bg-amber-950/80 text-amber-300 border-amber-700";
  } else if (status === "RESOLVED") {
    colorClasses = "bg-emerald-950/80 text-emerald-300 border-emerald-700";
  } else if (status === "CLOSED") {
    colorClasses = "bg-zinc-800/80 text-zinc-400 border-zinc-700";
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border tracking-wider ${colorClasses}`}
    >
      {status}
    </span>
  );
};

export const RiskScoreBadge: React.FC<{ score: number }> = ({ score }) => {
  let color = "text-emerald-400 border-emerald-800 bg-emerald-950/40";
  if (score >= 80) {
    color = "text-red-400 border-red-800 bg-red-950/40 animate-pulse";
  } else if (score >= 50) {
    color = "text-orange-400 border-orange-800 bg-orange-950/40";
  } else if (score >= 25) {
    color = "text-amber-400 border-amber-800 bg-amber-950/40";
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold border ${color}`}
      title="Closed-form bounded risk score [0, 100]"
    >
      RISK {score}/100
    </span>
  );
};
