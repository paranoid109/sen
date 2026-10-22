import React, { useState } from "react";
import { Shield, LogOut, UserCircle, Flame, Sparkles } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { SimulationModal } from "./SimulationModal";
import { AICopilotModal } from "./AICopilotModal";

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const [isSimOpen, setIsSimOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);

  const getRoleBadge = (role?: string) => {
    if (!role) return null;
    let badgeClass = "bg-slate-800 text-slate-300 border-slate-700";
    if (role === "Admin") badgeClass = "bg-red-950/80 text-red-300 border-red-800";
    if (role === "Analyst") badgeClass = "bg-blue-950/80 text-blue-300 border-blue-800";
    if (role === "Auditor") badgeClass = "bg-amber-950/80 text-amber-300 border-amber-800";

    return (
      <span
        className={`px-2 py-0.5 text-xs font-mono font-medium rounded border tracking-wider ${badgeClass}`}
      >
        {role}
      </span>
    );
  };

  return (
    <header className="sticky top-0 z-40 flex h-16 w-full items-center justify-between border-b border-cyber-border bg-cyber-surface/90 px-6 backdrop-blur-md">
      {/* Brand & Platform Badge */}
      <div className="flex items-center space-x-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyber-primary/10 border border-cyber-primary/30">
          <Shield className="h-6 w-6 text-cyber-primary" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-mono text-lg font-bold tracking-tight text-white">
              Sentinel<span className="text-cyber-primary">X</span>
            </span>
            <span className="rounded bg-cyber-primary/10 px-1.5 py-0.2 text-[10px] font-mono text-cyber-primary border border-cyber-primary/20">
              v1.0-SOC
            </span>
          </div>
          <p className="text-[11px] font-mono text-slate-400">Autonomous Cybersecurity Platform</p>
        </div>
      </div>

      {/* Heartbeat Status Indicator */}
      <div className="hidden md:flex items-center space-x-2 rounded-full border border-cyber-border bg-cyber-card px-3 py-1">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
        </span>
        <span className="font-mono text-xs font-medium text-emerald-400">SOC ARMED</span>
        <span className="text-slate-600">|</span>
        <span className="font-mono text-[11px] text-slate-400">DUAL-DB & HASH-CHAIN VERIFIED</span>
      </div>

      {/* User Info & Actions */}
      <div className="flex items-center space-x-4">
        {user && (
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <UserCircle className="h-5 w-5 text-slate-400" />
              <span className="font-mono text-xs text-slate-200 font-semibold">{user.username}</span>
            </div>
            {getRoleBadge(user.role)}
          </div>
        )}

        {/* AI Copilot Button */}
        <button
          onClick={() => setIsCopilotOpen(true)}
          className="flex items-center space-x-1.5 rounded-md border border-cyber-primary/40 bg-cyber-primary/10 px-3 py-1.5 text-xs font-mono font-medium text-cyber-primary transition-all hover:bg-cyber-primary/20 hover:border-cyber-primary shadow-sm"
          title="Open AI SOC Analyst Copilot"
        >
          <Sparkles className="h-3.5 w-3.5 text-cyber-primary" />
          <span>AI Copilot</span>
        </button>

        {/* Simulation Runner Button */}
        <button
          onClick={() => setIsSimOpen(true)}
          className="flex items-center space-x-1.5 rounded-md border border-red-800/60 bg-red-950/40 px-3 py-1.5 text-xs font-mono font-medium text-red-300 transition-all hover:bg-red-900/50 hover:border-red-600 shadow-sm"
          title="Open Red Team Attack Simulator"
        >
          <Flame className="h-3.5 w-3.5 text-red-400" />
          <span>Simulate Attack</span>
        </button>

        <button
          onClick={logout}
          className="flex items-center space-x-1.5 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-slate-300 transition-colors hover:border-red-800 hover:bg-red-950/30 hover:text-red-300"
          title="Sign out of SentinelX"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span>Logout</span>
        </button>
      </div>

      <SimulationModal isOpen={isSimOpen} onClose={() => setIsSimOpen(false)} />
      <AICopilotModal isOpen={isCopilotOpen} onClose={() => setIsCopilotOpen(false)} />
    </header>
  );
};
