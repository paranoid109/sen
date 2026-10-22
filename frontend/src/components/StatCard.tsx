import React from "react";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: "default" | "critical" | "warning" | "success" | "accent";
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "default",
}) => {
  let borderClass = "border-cyber-border";
  let iconClass = "text-cyber-primary bg-cyber-primary/10";

  if (variant === "critical") {
    borderClass = "border-red-800/80 bg-red-950/20";
    iconClass = "text-red-400 bg-red-950/50";
  } else if (variant === "warning") {
    borderClass = "border-amber-800/80 bg-amber-950/20";
    iconClass = "text-amber-400 bg-amber-950/50";
  } else if (variant === "success") {
    borderClass = "border-emerald-800/80 bg-emerald-950/20";
    iconClass = "text-emerald-400 bg-emerald-950/50";
  } else if (variant === "accent") {
    borderClass = "border-cyan-800/80 bg-cyan-950/20";
    iconClass = "text-cyan-400 bg-cyan-950/50";
  }

  return (
    <div
      className={`rounded-lg bg-cyber-surface border p-5 shadow-sm transition-all hover:border-slate-500 ${borderClass}`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-mono font-medium text-slate-400 uppercase tracking-wider">
            {title}
          </p>
          <p className="mt-2 text-3xl font-mono font-bold tracking-tight text-white">{value}</p>
          {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
        </div>
        <div className={`rounded-lg p-3 ${iconClass}`}>
          <Icon className="h-6 w-6" />
        </div>
      </div>
    </div>
  );
};
