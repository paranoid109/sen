import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Lock, User, AlertCircle, KeyRound } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export const Login: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(username, password);
      navigate("/");
    } catch (err: any) {
      if (err.response?.status === 429) {
        setError("Rate limit exceeded: Too many failed login attempts. Please wait 60 seconds.");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Authentication failed. Please verify credentials.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFillCredentials = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-bg p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-14 w-14 items-center justify-center rounded-xl bg-cyber-primary/10 border border-cyber-primary/30 glow-border">
            <Shield className="h-8 w-8 text-cyber-primary" />
          </div>
          <h1 className="font-mono text-2xl font-bold tracking-tight text-white">
            Sentinel<span className="text-cyber-primary">X</span> SOC Console
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Autonomous Incident Detection, Correlation & Response
          </p>
        </div>

        {/* Login Box */}
        <div className="rounded-xl border border-cyber-border bg-cyber-surface p-6 shadow-xl">
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="flex items-start space-x-2 rounded-lg border border-red-800 bg-red-950/40 p-3 text-xs text-red-300 font-mono">
                <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-mono font-medium text-slate-300">
                Username
              </label>
              <div className="relative mt-1">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                  <User className="h-4 w-4 text-slate-500" />
                </div>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyst"
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 pl-9 pr-3 text-sm text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none focus:ring-1 focus:ring-cyber-primary font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono font-medium text-slate-300">
                Password
              </label>
              <div className="relative mt-1">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                  <Lock className="h-4 w-4 text-slate-500" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 pl-9 pr-3 text-sm text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none focus:ring-1 focus:ring-cyber-primary font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-md bg-cyber-primary py-2 px-4 text-sm font-semibold text-cyber-bg transition-colors hover:bg-cyan-300 focus:outline-none focus:ring-2 focus:ring-cyber-primary focus:ring-offset-2 focus:ring-offset-cyber-bg disabled:opacity-50 font-mono"
            >
              {loading ? "Authenticating..." : "Sign In to SOC"}
            </button>
          </form>

          {/* Quick Credential Helpers */}
          <div className="mt-6 border-t border-cyber-border pt-4">
            <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-400 mb-2">
              <KeyRound className="h-3.5 w-3.5 text-cyber-primary" />
              <span>Development Access Personas:</span>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleFillCredentials("admin", "Admin123!Secure")}
                className="rounded border border-red-900/60 bg-red-950/20 py-1 px-2 text-[11px] font-mono text-red-300 hover:bg-red-950/50"
              >
                Admin
              </button>
              <button
                type="button"
                onClick={() => handleFillCredentials("analyst", "Analyst123!Secure")}
                className="rounded border border-blue-900/60 bg-blue-950/20 py-1 px-2 text-[11px] font-mono text-blue-300 hover:bg-blue-950/50"
              >
                Analyst
              </button>
              <button
                type="button"
                onClick={() => handleFillCredentials("auditor", "Auditor123!Secure")}
                className="rounded border border-amber-900/60 bg-amber-950/20 py-1 px-2 text-[11px] font-mono text-amber-300 hover:bg-amber-950/50"
              >
                Auditor
              </button>
            </div>
          </div>
        </div>

        <p className="text-center text-[11px] font-mono text-slate-500">
          Enforcing Session Storage & Law 4 Hash-Chained Audit Trails
        </p>
      </div>
    </div>
  );
};
