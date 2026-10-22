import React from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  Flame,
  Server,
  BarChart3,
  ShieldCheck,
  Cloud,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

export const Sidebar: React.FC = () => {
  const { hasRole } = useAuth();

  const navItems = [
    {
      to: "/",
      label: "SOC Dashboard",
      icon: LayoutDashboard,
      exact: true,
    },
    {
      to: "/alerts",
      label: "Alerts Queue",
      icon: ShieldAlert,
    },
    {
      to: "/incidents",
      label: "Incidents Console",
      icon: Flame,
    },
    {
      to: "/assets",
      label: "CMDB Assets",
      icon: Server,
    },
    {
      to: "/cloud",
      label: "Cloud Security",
      icon: Cloud,
    },
    {
      to: "/reports",
      label: "Reports & KPI",
      icon: BarChart3,
    },
  ];

  // Admin and Auditor can access Admin & Audit
  const showAdmin = hasRole(["Admin", "Auditor"]);

  return (
    <aside className="w-64 border-r border-cyber-border bg-cyber-surface/50 p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-6">
        <div>
          <p className="px-3 text-[11px] font-mono font-medium text-slate-500 uppercase tracking-wider">
            Operational SOC
          </p>
          <nav className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.exact}
                  className={({ isActive }) =>
                    `flex items-center space-x-3 rounded-md px-3 py-2 text-sm font-medium transition-all ${
                      isActive
                        ? "bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/30 font-semibold"
                        : "text-slate-400 hover:bg-cyber-card hover:text-slate-200"
                    }`
                  }
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {showAdmin && (
          <div>
            <p className="px-3 text-[11px] font-mono font-medium text-slate-500 uppercase tracking-wider">
              Governance & Audit
            </p>
            <nav className="mt-2 space-y-1">
              <NavLink
                to="/admin"
                className={({ isActive }) =>
                  `flex items-center space-x-3 rounded-md px-3 py-2 text-sm font-medium transition-all ${
                    isActive
                      ? "bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/30 font-semibold"
                      : "text-slate-400 hover:bg-cyber-card hover:text-slate-200"
                  }`
                }
              >
                <ShieldCheck className="h-4 w-4 shrink-0 text-amber-400" />
                <span>Admin & Audit Trail</span>
              </NavLink>
            </nav>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-cyber-border bg-cyber-card/60 p-3">
        <p className="font-mono text-xs font-semibold text-slate-300">Architecture Guard</p>
        <p className="mt-1 text-[11px] text-slate-400 leading-normal">
          Strict Law 1 (Decoupled Core) & Law 4 (Hash-Chained Audit) enforced.
        </p>
      </div>
    </aside>
  );
};
