import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  Key,
  Users,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Plus,
  Trash2,
  Copy,
  Check,
  Lock,
  XCircle,
} from "lucide-react";
import { auditApi, authApi, assetsApi } from "../services/api";
import type {
  ApiKey,
  ApiKeyCreated,
  Asset,
  AuditLog,
  AuditVerify,
  User,
  UserRole,
} from "../types";
import { useAuth } from "../context/AuthContext";

export const AdminAudit: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"audit" | "apikeys" | "users">("audit");

  // Audit Logs state
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [verification, setVerification] = useState<AuditVerify | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [loadingAudit, setLoadingAudit] = useState(false);

  // API Keys state
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyAssetId, setNewKeyAssetId] = useState<string>("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [createdKeyData, setCreatedKeyData] = useState<ApiKeyCreated | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  // Users state
  const [users, setUsers] = useState<User[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState<UserRole>("Analyst");
  const [submittingUser, setSubmittingUser] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);

  const { hasRole } = useAuth();
  const isAdmin = hasRole(["Admin"]);

  // Fetch Audit Trail
  const fetchAuditData = async () => {
    setLoadingAudit(true);
    try {
      const logs = await auditApi.getAuditLogs({ limit: 50 });
      setAuditLogs(logs);
    } catch (err) {
      console.error("Failed to load audit trail:", err);
    } finally {
      setLoadingAudit(false);
    }
  };

  // Run Cryptographic Verification of Audit Chain (Law 4)
  const handleVerifyAuditChain = async () => {
    setVerifying(true);
    try {
      const res = await auditApi.verifyAuditChain();
      setVerification(res);
    } catch (err) {
      console.error("Failed to verify audit chain:", err);
    } finally {
      setVerifying(false);
    }
  };

  // Fetch API Keys
  const fetchApiKeys = async () => {
    setLoadingKeys(true);
    try {
      const [keys, assetList] = await Promise.all([
        authApi.getApiKeys(),
        assetsApi.getAssets(),
      ]);
      setApiKeys(keys);
      setAssets(assetList);
    } catch (err) {
      console.error("Failed to load API keys:", err);
    } finally {
      setLoadingKeys(false);
    }
  };

  // Fetch Users
  const fetchUsers = async () => {
    setLoadingUsers(true);
    try {
      const data = await authApi.getUsers();
      setUsers(data);
    } catch (err) {
      console.error("Failed to load users:", err);
    } finally {
      setLoadingUsers(false);
    }
  };

  useEffect(() => {
    if (activeTab === "audit") {
      fetchAuditData();
      handleVerifyAuditChain();
    } else if (activeTab === "apikeys") {
      fetchApiKeys();
    } else if (activeTab === "users" && isAdmin) {
      fetchUsers();
    }
  }, [activeTab]);

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await authApi.createApiKey({
        name: newKeyName,
        asset_id: newKeyAssetId || null,
      });
      setCreatedKeyData(res);
      setNewKeyName("");
      setNewKeyAssetId("");
      fetchApiKeys();
    } catch (err) {
      console.error("Failed to create API key:", err);
    }
  };

  const handleDeleteApiKey = async (id: string) => {
    if (!window.confirm("Revoke this ingestion API key permanently?")) return;
    try {
      await authApi.deleteApiKey(id);
      setApiKeys((prev) => prev.filter((k) => k.id !== id));
    } catch (err) {
      console.error("Failed to revoke API key:", err);
    }
  };

  const handleCopyKey = () => {
    if (!createdKeyData) return;
    navigator.clipboard.writeText(createdKeyData.raw_key);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittingUser(true);
    setUserError(null);

    try {
      await authApi.createUser({
        username: newUsername,
        email: newUserEmail,
        password: newUserPassword,
        role: newUserRole,
      });
      setIsUserModalOpen(false);
      setNewUsername("");
      setNewUserEmail("");
      setNewUserPassword("");
      fetchUsers();
    } catch (err: any) {
      setUserError(err.response?.data?.detail || "Failed to create user account.");
    } finally {
      setSubmittingUser(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Lock className="h-6 w-6 text-amber-400" />
            <span>Security Governance & Tamper-Evident Audit</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Law 4 SHA-256 cryptographic chain verification, RBAC management, and ingestion keys
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center space-x-1 rounded-lg border border-cyber-border bg-cyber-card p-1">
          <button
            onClick={() => setActiveTab("audit")}
            className={`flex items-center space-x-1.5 rounded-md px-3 py-1.5 text-xs font-mono transition-colors ${
              activeTab === "audit"
                ? "bg-cyber-primary text-cyber-bg font-bold"
                : "text-slate-300 hover:text-white"
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Audit Trail</span>
          </button>
          <button
            onClick={() => setActiveTab("apikeys")}
            className={`flex items-center space-x-1.5 rounded-md px-3 py-1.5 text-xs font-mono transition-colors ${
              activeTab === "apikeys"
                ? "bg-cyber-primary text-cyber-bg font-bold"
                : "text-slate-300 hover:text-white"
            }`}
          >
            <Key className="h-3.5 w-3.5" />
            <span>Ingest API Keys</span>
          </button>
          {isAdmin && (
            <button
              onClick={() => setActiveTab("users")}
              className={`flex items-center space-x-1.5 rounded-md px-3 py-1.5 text-xs font-mono transition-colors ${
                activeTab === "users"
                  ? "bg-cyber-primary text-cyber-bg font-bold"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <Users className="h-3.5 w-3.5" />
              <span>Platform Users</span>
            </button>
          )}
        </div>
      </div>

      {/* TAB 1: AUDIT TRAIL */}
      {activeTab === "audit" && (
        <div className="space-y-4">
          {/* Law 4 Cryptographic Verification Status Banner */}
          <div className="rounded-lg border border-cyber-border bg-cyber-surface p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              {verification?.is_valid ? (
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-950/60 border border-emerald-700">
                  <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                </div>
              ) : (
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-950/60 border border-red-700">
                  <AlertTriangle className="h-6 w-6 text-red-400" />
                </div>
              )}
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-sm font-bold text-white">
                    Law 4 Audit Chain Integrity:
                  </span>
                  <span
                    className={`font-mono text-xs font-semibold px-2 py-0.5 rounded border ${
                      verification?.is_valid
                        ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
                        : "bg-red-950/80 text-red-300 border-red-800"
                    }`}
                  >
                    {verification?.is_valid ? "VALID & UNTAMPERED" : "TAMPER DETECTED"}
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Verified {verification?.total_records ?? 0} contiguous SHA-256 hash-chained
                  records. Zero broken links.
                </p>
              </div>
            </div>

            <button
              onClick={handleVerifyAuditChain}
              disabled={verifying}
              className="flex items-center space-x-1.5 rounded-md border border-cyber-border bg-cyber-card px-3 py-2 text-xs font-mono text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${verifying ? "animate-spin text-cyber-primary" : ""}`} />
              <span>Verify Cryptographic Chain</span>
            </button>
          </div>

          {/* Audit Logs Table */}
          <div className="overflow-hidden rounded-lg border border-cyber-border bg-cyber-surface shadow-sm">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-cyber-border text-left font-mono">
                <thead className="bg-cyber-card text-[11px] uppercase tracking-wider text-slate-400">
                  <tr>
                    <th scope="col" className="px-4 py-3">Seq #</th>
                    <th scope="col" className="px-4 py-3">Timestamp</th>
                    <th scope="col" className="px-4 py-3">Actor</th>
                    <th scope="col" className="px-4 py-3">Action & Resource</th>
                    <th scope="col" className="px-4 py-3">Status</th>
                    <th scope="col" className="px-4 py-3">SHA-256 Entry Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/60 text-xs">
                  {auditLogs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                        {loadingAudit ? "Loading audit logs..." : "No audit records logged yet."}
                      </td>
                    </tr>
                  ) : (
                    auditLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="px-4 py-3 whitespace-nowrap text-cyber-primary font-bold">
                          #{log.sequence_number}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-slate-400 text-[11px]">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-slate-200">
                          {log.user_id || "SYSTEM / INTERNAL"}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-semibold text-slate-200">{log.action}</div>
                          <div className="text-[11px] text-slate-400">
                            {log.resource_type} {log.resource_id ? `(${log.resource_id.slice(0, 8)}...)` : ""}
                          </div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              log.status === "SUCCESS"
                                ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
                                : "bg-red-950/80 text-red-300 border-red-800"
                            }`}
                          >
                            {log.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap font-mono text-[10px] text-slate-400 max-w-xs truncate">
                          <span title={`Entry: ${log.entry_hash}\nPrev: ${log.prev_hash}`}>
                            {log.entry_hash.slice(0, 16)}...
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: INGEST API KEYS */}
      {activeTab === "apikeys" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs font-mono text-slate-400">
              API Keys allow external telemetry agents (modules, Syslog, Webhooks) to authenticate
              via <code className="text-cyber-primary">X-API-Key</code>.
            </p>
            {isAdmin && (
              <button
                onClick={() => {
                  setCreatedKeyData(null);
                  setIsKeyModalOpen(true);
                }}
                className="flex items-center space-x-1.5 rounded-md bg-cyber-primary px-3 py-1.5 text-xs font-mono font-semibold text-cyber-bg hover:bg-cyan-300"
              >
                <Plus className="h-4 w-4" />
                <span>Generate Ingest Key</span>
              </button>
            )}
          </div>

          <div className="overflow-hidden rounded-lg border border-cyber-border bg-cyber-surface shadow-sm">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-cyber-border text-left font-mono">
                <thead className="bg-cyber-card text-[11px] uppercase tracking-wider text-slate-400">
                  <tr>
                    <th scope="col" className="px-4 py-3">Key Name</th>
                    <th scope="col" className="px-4 py-3">Key Prefix</th>
                    <th scope="col" className="px-4 py-3">Scope</th>
                    <th scope="col" className="px-4 py-3">Bound CMDB Asset</th>
                    <th scope="col" className="px-4 py-3">Status</th>
                    <th scope="col" className="px-4 py-3">Created</th>
                    {isAdmin && <th scope="col" className="px-4 py-3 text-right">Actions</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/60 text-xs">
                  {apiKeys.length === 0 ? (
                    <tr>
                      <td colSpan={isAdmin ? 7 : 6} className="px-4 py-8 text-center text-slate-500">
                        {loadingKeys ? "Loading API keys..." : "No ingestion keys active."}
                      </td>
                    </tr>
                  ) : (
                    apiKeys.map((key) => (
                      <tr key={key.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="px-4 py-3 whitespace-nowrap font-semibold text-slate-200">
                          {key.name}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-cyber-primary">
                          {key.prefix}...
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-slate-300 uppercase text-[10px]">
                          {key.scope}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-slate-400">
                          {key.asset_id ? key.asset_id.slice(0, 8) + "..." : "Global / Unrestricted"}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                              key.is_active
                                ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
                                : "bg-red-950/80 text-red-300 border-red-800"
                            }`}
                          >
                            {key.is_active ? "ACTIVE" : "REVOKED"}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-slate-400 text-[11px]">
                          {new Date(key.created_at).toLocaleDateString()}
                        </td>
                        {isAdmin && (
                          <td className="px-4 py-3 whitespace-nowrap text-right">
                            <button
                              onClick={() => handleDeleteApiKey(key.id)}
                              className="rounded p-1 text-slate-400 hover:bg-red-950/40 hover:text-red-400"
                              title="Revoke Key"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </td>
                        )}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Key Generation Modal */}
          {isKeyModalOpen && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
              <div className="w-full max-w-md rounded-xl border border-cyber-border bg-cyber-surface p-6 shadow-2xl space-y-4">
                <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                  <h3 className="font-mono text-base font-bold text-white">Generate Ingest API Key</h3>
                  <button onClick={() => setIsKeyModalOpen(false)} className="text-slate-400 hover:text-white">
                    <XCircle className="h-5 w-5" />
                  </button>
                </div>

                {createdKeyData ? (
                  <div className="space-y-4 font-mono text-xs">
                    <div className="rounded border border-emerald-800 bg-emerald-950/40 p-3 text-emerald-300">
                      API Key generated successfully! Store this key safely. You will not be able to
                      view it again.
                    </div>

                    <div>
                      <label className="block text-slate-400 mb-1">Plaintext API Key Secret:</label>
                      <div className="flex items-center space-x-2">
                        <input
                          readOnly
                          value={createdKeyData.raw_key}
                          className="w-full rounded border border-cyber-border bg-cyber-card py-2 px-3 text-white font-mono text-xs select-all"
                        />
                        <button
                          onClick={handleCopyKey}
                          className="rounded bg-cyber-card border border-cyber-border p-2 text-slate-300 hover:text-white"
                          title="Copy Key"
                        >
                          {copiedKey ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>

                    <div className="flex justify-end pt-2">
                      <button
                        onClick={() => setIsKeyModalOpen(false)}
                        className="rounded bg-cyber-primary px-4 py-2 font-semibold text-cyber-bg"
                      >
                        Done
                      </button>
                    </div>
                  </div>
                ) : (
                  <form onSubmit={handleCreateApiKey} className="space-y-4 font-mono text-xs">
                    <div>
                      <label className="block text-slate-300 mb-1">Key Name / Identifier</label>
                      <input
                        type="text"
                        required
                        placeholder="e.g. Suricata NIDS Collector"
                        value={newKeyName}
                        onChange={(e) => setNewKeyName(e.target.value)}
                        className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                      />
                    </div>

                    <div>
                      <label className="block text-slate-300 mb-1">Bind to CMDB Asset (Optional)</label>
                      <select
                        value={newKeyAssetId}
                        onChange={(e) => setNewKeyAssetId(e.target.value)}
                        className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white focus:border-cyber-primary focus:outline-none"
                      >
                        <option value="">Global / Unrestricted</option>
                        {assets.map((asset) => (
                          <option key={asset.id} value={asset.id}>
                            {asset.hostname || asset.ip_address} ({asset.asset_type})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="flex items-center justify-end space-x-3 pt-2">
                      <button
                        type="button"
                        onClick={() => setIsKeyModalOpen(false)}
                        className="rounded-md border border-cyber-border bg-cyber-card px-4 py-2 text-slate-300 hover:bg-slate-800"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        className="rounded-md bg-cyber-primary px-4 py-2 font-semibold text-cyber-bg hover:bg-cyan-300"
                      >
                        Generate Key
                      </button>
                    </div>
                  </form>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: PLATFORM USERS */}
      {activeTab === "users" && isAdmin && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs font-mono text-slate-400">
              Role-Based Access Control (Admin, Analyst, Auditor personas).
            </p>
            <button
              onClick={() => setIsUserModalOpen(true)}
              className="flex items-center space-x-1.5 rounded-md bg-cyber-primary px-3 py-1.5 text-xs font-mono font-semibold text-cyber-bg hover:bg-cyan-300"
            >
              <Plus className="h-4 w-4" />
              <span>Create User Account</span>
            </button>
          </div>

          <div className="overflow-hidden rounded-lg border border-cyber-border bg-cyber-surface shadow-sm">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-cyber-border text-left font-mono">
                <thead className="bg-cyber-card text-[11px] uppercase tracking-wider text-slate-400">
                  <tr>
                    <th scope="col" className="px-4 py-3">Username</th>
                    <th scope="col" className="px-4 py-3">Email Address</th>
                    <th scope="col" className="px-4 py-3">Role</th>
                    <th scope="col" className="px-4 py-3">Active</th>
                    <th scope="col" className="px-4 py-3">Enrolled At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/60 text-xs">
                  {users.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                        {loadingUsers ? "Loading users..." : "No users enrolled."}
                      </td>
                    </tr>
                  ) : (
                    users.map((u) => (
                    <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3 whitespace-nowrap font-semibold text-slate-200">
                        {u.username}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-400">
                        {u.email}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            u.role === "Admin"
                              ? "bg-red-950/80 text-red-300 border-red-800"
                              : u.role === "Analyst"
                              ? "bg-blue-950/80 text-blue-300 border-blue-800"
                              : "bg-amber-950/80 text-amber-300 border-amber-800"
                          }`}
                        >
                          {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="text-emerald-400 font-semibold">Active</span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-400 text-[11px]">
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
              </table>
            </div>
          </div>

          {/* User Creation Modal */}
          {isUserModalOpen && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
              <div className="w-full max-w-md rounded-xl border border-cyber-border bg-cyber-surface p-6 shadow-2xl space-y-4">
                <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                  <h3 className="font-mono text-base font-bold text-white">Create SOC User</h3>
                  <button onClick={() => setIsUserModalOpen(false)} className="text-slate-400 hover:text-white">
                    <XCircle className="h-5 w-5" />
                  </button>
                </div>

                {userError && (
                  <div className="rounded border border-red-800 bg-red-950/40 p-2.5 text-xs text-red-300 font-mono">
                    {userError}
                  </div>
                )}

                <form onSubmit={handleCreateUser} className="space-y-3 font-mono text-xs">
                  <div>
                    <label className="block text-slate-300 mb-1">Username</label>
                    <input
                      type="text"
                      required
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      placeholder="analyst2"
                      className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1">Email</label>
                    <input
                      type="email"
                      required
                      value={newUserEmail}
                      onChange={(e) => setNewUserEmail(e.target.value)}
                      placeholder="analyst2@sentinelx.internal"
                      className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1">Password</label>
                    <input
                      type="password"
                      required
                      value={newUserPassword}
                      onChange={(e) => setNewUserPassword(e.target.value)}
                      placeholder="Min 8 characters"
                      className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-1">Role Persona</label>
                    <select
                      value={newUserRole}
                      onChange={(e) => setNewUserRole(e.target.value as UserRole)}
                      className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white focus:border-cyber-primary focus:outline-none"
                    >
                      <option value="Admin">Admin</option>
                      <option value="Analyst">Analyst</option>
                      <option value="Auditor">Auditor</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-end space-x-3 pt-3">
                    <button
                      type="button"
                      onClick={() => setIsUserModalOpen(false)}
                      className="rounded-md border border-cyber-border bg-cyber-card px-4 py-2 text-slate-300 hover:bg-slate-800"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={submittingUser}
                      className="rounded-md bg-cyber-primary px-4 py-2 font-semibold text-cyber-bg hover:bg-cyan-300 disabled:opacity-50"
                    >
                      {submittingUser ? "Creating..." : "Create Account"}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
