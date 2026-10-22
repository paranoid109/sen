import React from "react";
import {
  Clock,
  ShieldAlert,
  Activity,
  User,
  Server,
  Lock,
  FileCheck,
  RotateCcw,
} from "lucide-react";
import type { IncidentTimelineItem } from "../types";

export const IncidentTimeline: React.FC<{ items: IncidentTimelineItem[] }> = ({ items }) => {
  if (!items || items.length === 0) {
    return (
      <div className="py-6 text-center text-sm text-slate-500 font-mono">
        No chronological timeline events recorded for this incident.
      </div>
    );
  }

  const getEventBadge = (eventType: string, source: string) => {
    const et = eventType.toLowerCase();
    const s = source.toLowerCase();
    if (et.includes("rollback")) {
      return {
        icon: <RotateCcw className="h-4 w-4 text-amber-400" />,
        badgeClass: "bg-amber-950/60 text-amber-300 border-amber-500/40",
      };
    }
    if (s.includes("soar") || et.includes("containment")) {
      return {
        icon: <Lock className="h-4 w-4 text-cyan-400" />,
        badgeClass: "bg-cyan-950/60 text-cyan-300 border-cyan-500/40",
      };
    }
    if (s.includes("forensic") || et.includes("forensic")) {
      return {
        icon: <FileCheck className="h-4 w-4 text-purple-400" />,
        badgeClass: "bg-purple-950/60 text-purple-300 border-purple-500/40",
      };
    }
    if (s.includes("alert") || s.includes("rule")) {
      return {
        icon: <ShieldAlert className="h-4 w-4 text-orange-400" />,
        badgeClass: "bg-orange-950/60 text-orange-300 border-orange-500/40",
      };
    }
    if (s.includes("user") || s.includes("analyst") || s.includes("admin")) {
      return {
        icon: <User className="h-4 w-4 text-cyber-primary" />,
        badgeClass: "bg-cyber-primary/20 text-cyber-primary border-cyber-primary/30",
      };
    }
    if (s.includes("asset") || s.includes("host")) {
      return {
        icon: <Server className="h-4 w-4 text-emerald-400" />,
        badgeClass: "bg-emerald-950/60 text-emerald-300 border-emerald-500/40",
      };
    }
    return {
      icon: <Activity className="h-4 w-4 text-slate-400" />,
      badgeClass: "bg-slate-800 text-slate-300 border-slate-700",
    };
  };

  return (
    <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-cyber-border">
      {items.map((item, idx) => {
        const { icon, badgeClass } = getEventBadge(item.event_type, item.source);
        return (
          <div key={item.id || idx} className="relative group">
            {/* Timeline marker */}
            <div className="absolute -left-6 mt-1 flex h-4 w-4 items-center justify-center rounded-full bg-cyber-surface border-2 border-cyber-primary">
              <span className="h-1.5 w-1.5 rounded-full bg-cyber-primary"></span>
            </div>

            <div className="rounded-lg border border-cyber-border bg-cyber-card p-3 shadow-sm transition-all hover:border-slate-500">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-cyber-border/60 pb-2">
                <div className="flex items-center space-x-2">
                  {icon}
                  <span
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${badgeClass}`}
                  >
                    {item.event_type}
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    | Source: {item.source}
                  </span>
                </div>
                <div className="flex items-center space-x-1 text-xs text-slate-400 font-mono">
                  <Clock className="h-3 w-3" />
                  <span>{new Date(item.timestamp).toLocaleString()}</span>
                </div>
              </div>

              <p className="mt-2 text-sm text-slate-300 font-sans leading-relaxed">
                {item.description}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
};
