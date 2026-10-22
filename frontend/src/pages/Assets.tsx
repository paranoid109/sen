import React, { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  Server,
  Plus,
  Trash2,
  RefreshCw,
  Search,
  XCircle,
  ShieldAlert,
  Flame,
  Table,
  Network,
} from "lucide-react";
import { assetsApi } from "../services/api";
import type { Asset, AssetCreate, SeverityLevel } from "../types";
import { SeverityBadge } from "../components/AlertBadge";
import { TopologyGraph } from "../components/TopologyGraph";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";

export const Assets: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlSearch = searchParams.get("search") || "";

  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState(urlSearch);
  const [viewMode, setViewMode] = useState<"table" | "topology">("table");

  // New Asset Modal
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newHostname, setNewHostname] = useState("");
  const [newIpAddress, setNewIpAddress] = useState("");
  const [newAssetType, setNewAssetType] = useState("server");
  const [newCriticality, setNewCriticality] = useState<SeverityLevel>("medium");
  const [newDescription, setNewDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const { hasRole } = useAuth();
  const { showToast } = useToast();
  const isAdmin = hasRole(["Admin"]);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const data = await assetsApi.getAssets();
      setAssets(data);
    } catch (err) {
      console.error("Failed to load CMDB assets:", err);
      showToast("Failed to load CMDB assets", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleSearchChange = (val: string) => {
    setSearchQuery(val);
    const newParams = new URLSearchParams(searchParams);
    if (val.trim()) {
      newParams.set("search", val.trim());
    } else {
      newParams.delete("search");
    }
    setSearchParams(newParams);
  };

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setErrorMsg(null);

    try {
      const payload: AssetCreate = {
        hostname: newHostname || null,
        ip_address: newIpAddress || null,
        asset_type: newAssetType,
        criticality: newCriticality,
        description: newDescription || null,
      };

      const created = await assetsApi.createAsset(payload);
      setAssets((prev) => [created, ...prev]);
      setIsModalOpen(false);
      setNewHostname("");
      setNewIpAddress("");
      setNewDescription("");
      showToast("Asset successfully enrolled in CMDB", "success");
    } catch (err: any) {
      const msg = err.response?.data?.detail || "Failed to create CMDB asset.";
      setErrorMsg(msg);
      showToast(msg, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteAsset = async (id: string) => {
    if (!window.confirm("Are you sure you want to remove this asset from CMDB?")) return;
    try {
      await assetsApi.deleteAsset(id);
      setAssets((prev) => prev.filter((a) => a.id !== id));
      showToast("Asset removed from CMDB", "info");
    } catch (err) {
      console.error("Failed to delete asset:", err);
      showToast("Failed to delete asset", "error");
    }
  };

  const filteredAssets = assets.filter((asset) => {
    const q = searchQuery.toLowerCase();
    const host = (asset.hostname || "").toLowerCase();
    const ip = (asset.ip_address || "").toLowerCase();
    const type = (asset.asset_type || "").toLowerCase();
    return host.includes(q) || ip.includes(q) || type.includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Server className="h-6 w-6 text-cyan-400" />
            <span>Monitored CMDB Asset Inventory</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300 border border-slate-700">
              {assets.length} Enrolled
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Asset context enrichment, criticality weightings, and monitored infrastructure targets
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* View Mode Switcher */}
          <div className="flex items-center rounded-md border border-cyber-border bg-cyber-card p-0.5">
            <button
              onClick={() => setViewMode("table")}
              className={`flex items-center space-x-1.5 rounded px-2.5 py-1 text-xs font-mono transition-colors ${
                viewMode === "table"
                  ? "bg-slate-700 text-cyan-300 font-semibold shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <Table className="h-3.5 w-3.5" />
              <span>Inventory Table</span>
            </button>
            <button
              onClick={() => setViewMode("topology")}
              className={`flex items-center space-x-1.5 rounded px-2.5 py-1 text-xs font-mono transition-colors ${
                viewMode === "topology"
                  ? "bg-slate-700 text-cyan-300 font-semibold shadow-sm"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <Network className="h-3.5 w-3.5" />
              <span>Attack Graph & Topology</span>
            </button>
          </div>

          {viewMode === "table" && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search host, IP, type..."
                value={searchQuery}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="w-48 sm:w-64 rounded-md border border-cyber-border bg-cyber-card py-1.5 pl-8 pr-3 text-xs font-mono text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
              />
            </div>
          )}

          <button
            onClick={fetchAssets}
            className="flex items-center space-x-1.5 rounded-md border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyber-primary" : ""}`} />
            <span>Refresh</span>
          </button>

          {isAdmin && (
            <button
              onClick={() => setIsModalOpen(true)}
              className="flex items-center space-x-1.5 rounded-md bg-cyber-primary px-3 py-1.5 text-xs font-mono font-semibold text-cyber-bg hover:bg-cyan-300"
            >
              <Plus className="h-4 w-4" />
              <span>Register Asset</span>
            </button>
          )}
        </div>
      </div>

      {/* Asset Grid / Table or Attack Graph */}
      {viewMode === "topology" ? (
        <TopologyGraph cmdbAssets={assets} />
      ) : (
        <div className="overflow-hidden rounded-lg border border-cyber-border bg-cyber-surface shadow-sm">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-cyber-border text-left font-mono">
              <thead className="bg-cyber-card text-[11px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th scope="col" className="px-4 py-3">Hostname / FQDN</th>
                  <th scope="col" className="px-4 py-3">IP Address</th>
                  <th scope="col" className="px-4 py-3">Asset Type</th>
                  <th scope="col" className="px-4 py-3">Criticality</th>
                  <th scope="col" className="px-4 py-3">Description</th>
                  <th scope="col" className="px-4 py-3">Enrolled At</th>
                  <th scope="col" className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/60 text-xs">
                {filteredAssets.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                      {loading ? "Loading assets..." : "No CMDB assets found matching query."}
                    </td>
                  </tr>
                ) : (
                  filteredAssets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="font-semibold text-slate-200">{asset.hostname || "N/A"}</div>
                        <div className="text-[10px] text-slate-500">ID: {asset.id}</div>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-300">
                        {asset.ip_address || "DHCP / Unassigned"}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-cyber-card border border-cyber-border text-slate-300 uppercase text-[10px]">
                          {asset.asset_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <SeverityBadge severity={asset.criticality} />
                      </td>
                      <td className="px-4 py-3 text-slate-400 max-w-xs truncate">
                        {asset.description || "--"}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-400 text-[11px]">
                        {new Date(asset.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-right space-x-2">
                        <Link
                          to={`/alerts?search=${asset.hostname || asset.ip_address || ""}`}
                          className="inline-flex items-center space-x-1 rounded border border-cyber-border bg-cyber-card px-2 py-1 text-[11px] text-slate-300 hover:border-red-500 hover:text-red-300 transition-colors"
                          title="View alerts on this asset"
                        >
                          <ShieldAlert className="h-3 w-3 text-red-400" />
                          <span>Alerts</span>
                        </Link>
                        <Link
                          to={`/incidents?search=${asset.hostname || asset.ip_address || ""}`}
                          className="inline-flex items-center space-x-1 rounded border border-cyber-border bg-cyber-card px-2 py-1 text-[11px] text-slate-300 hover:border-orange-500 hover:text-orange-300 transition-colors"
                          title="View incidents on this asset"
                        >
                          <Flame className="h-3 w-3 text-orange-400" />
                          <span>Cases</span>
                        </Link>
                        {isAdmin && (
                          <button
                            onClick={() => handleDeleteAsset(asset.id)}
                            className="rounded p-1 text-slate-400 hover:bg-red-950/40 hover:text-red-400 transition-colors"
                            title="Delete Asset"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Asset Registration Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-cyber-border bg-cyber-surface p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <h3 className="font-mono text-base font-bold text-white">Enroll CMDB Asset</h3>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-white">
                <XCircle className="h-5 w-5" />
              </button>
            </div>

            {errorMsg && (
              <div className="rounded border border-red-800 bg-red-950/40 p-2.5 text-xs text-red-300 font-mono">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleCreateAsset} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Hostname / FQDN</label>
                <input
                  type="text"
                  placeholder="e.g. prod-db-01.corp.internal"
                  value={newHostname}
                  onChange={(e) => setNewHostname(e.target.value)}
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">IP Address</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.100"
                  value={newIpAddress}
                  onChange={(e) => setNewIpAddress(e.target.value)}
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Asset Type</label>
                  <select
                    value={newAssetType}
                    onChange={(e) => setNewAssetType(e.target.value)}
                    className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white focus:border-cyber-primary focus:outline-none"
                  >
                    <option value="server">Server</option>
                    <option value="workstation">Workstation</option>
                    <option value="firewall">Firewall</option>
                    <option value="router">Router</option>
                    <option value="database">Database</option>
                    <option value="cloud_instance">Cloud Instance</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 mb-1">Criticality</label>
                  <select
                    value={newCriticality}
                    onChange={(e) => setNewCriticality(e.target.value as SeverityLevel)}
                    className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white focus:border-cyber-primary focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Description / Notes</label>
                <textarea
                  rows={2}
                  placeholder="Primary database hosting enterprise customer credentials"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full rounded-md border border-cyber-border bg-cyber-card py-2 px-3 text-white placeholder-slate-500 focus:border-cyber-primary focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-3">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="rounded-md border border-cyber-border bg-cyber-card px-4 py-2 text-slate-300 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="rounded-md bg-cyber-primary px-4 py-2 font-semibold text-cyber-bg hover:bg-cyan-300 disabled:opacity-50"
                >
                  {submitting ? "Registering..." : "Enroll Asset"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
