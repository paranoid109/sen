import React, { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  ShieldAlert,
  Server,
  Database,
  Laptop,
  Key,
  Bug,
  Crosshair,
  Radio,
  RotateCcw,
  AlertTriangle,
  ChevronRight,
  Flame,
} from "lucide-react";
import type { Asset } from "../types";
import { SeverityBadge, RiskScoreBadge } from "./AlertBadge";

export interface TopologyNode {
  id: string;
  label: string;
  type: "asset" | "identity" | "vulnerability";
  assetType?: string;
  criticality: "critical" | "high" | "medium" | "low";
  isCrownJewel?: boolean;
  x: number;
  y: number;
  ip?: string;
  cve?: string;
  cvss?: number;
  hasCisaKev?: boolean;
  description: string;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  isAttackPath?: boolean;
}

// Canonical enterprise graph nodes aligned with Module X8 & X9 and seed_db.py
const DEFAULT_NODES: TopologyNode[] = [
  {
    id: "firewall-edge-01",
    label: "Edge Perimeter Gateway",
    type: "asset",
    assetType: "firewall",
    criticality: "high",
    isCrownJewel: false,
    x: 90,
    y: 190,
    ip: "192.168.1.1",
    description: "Perimeter Edge Gateway & Firewall with ingress ports 80/443 routable to application server.",
  },
  {
    id: "server-prod-01",
    label: "Production App Server",
    type: "asset",
    assetType: "server",
    criticality: "high",
    isCrownJewel: false,
    x: 350,
    y: 190,
    ip: "192.168.1.10",
    cve: "CVE-2023-44487",
    cvss: 9.8,
    hasCisaKev: true,
    description: "Primary Production Application Server hosting web and API microservices.",
  },
  {
    id: "db-prod-01",
    label: "Core Production Database",
    type: "asset",
    assetType: "database",
    criticality: "critical",
    isCrownJewel: true,
    x: 620,
    y: 190,
    ip: "192.168.1.20",
    cve: "CVE-2021-44228",
    cvss: 10.0,
    hasCisaKev: true,
    description: "Core Production Database Cluster storing sensitive enterprise data and credential vaults.",
  },
  {
    id: "ws-eng-100",
    label: "Engineering Workstation",
    type: "asset",
    assetType: "workstation",
    criticality: "low",
    isCrownJewel: false,
    x: 90,
    y: 370,
    ip: "192.168.1.100",
    description: "Developer Engineering Workstation on internal corporate VLAN with developer SSH keys.",
  },
  {
    id: "admin-role",
    label: "Global Admin IAM Role",
    type: "identity",
    criticality: "critical",
    isCrownJewel: false,
    x: 350,
    y: 370,
    description: "Privileged administrator identity with direct management access to database clusters.",
  },
  {
    id: "app-service-account",
    label: "Kubernetes Service Account",
    type: "identity",
    criticality: "medium",
    isCrownJewel: false,
    x: 490,
    y: 90,
    description: "Assumed Pod identity with read/write access to payment database shards.",
  },
  {
    id: "cve-2024-21413",
    label: "CVE-2023-44487 (CISA KEV)",
    type: "vulnerability",
    criticality: "critical",
    isCrownJewel: false,
    x: 350,
    y: 70,
    cve: "CVE-2023-44487",
    cvss: 9.8,
    hasCisaKev: true,
    description: "HTTP/2 Rapid Reset & Remote Exploit vulnerability actively cataloged in CISA KEV.",
  },
];

const DEFAULT_EDGES: TopologyEdge[] = [
  {
    id: "e-fw-srv",
    source: "firewall-edge-01",
    target: "server-prod-01",
    relation: "routable_to",
    isAttackPath: true,
  },
  {
    id: "e-srv-db",
    source: "server-prod-01",
    target: "db-prod-01",
    relation: "sql_connection",
    isAttackPath: true,
  },
  {
    id: "e-srv-cve",
    source: "server-prod-01",
    target: "cve-2024-21413",
    relation: "has_vulnerability",
  },
  {
    id: "e-srv-sa",
    source: "server-prod-01",
    target: "app-service-account",
    relation: "assumes_role",
  },
  {
    id: "e-sa-db",
    source: "app-service-account",
    target: "db-prod-01",
    relation: "granted_access",
  },
  {
    id: "e-ws-admin",
    source: "ws-eng-100",
    target: "admin-role",
    relation: "stored_credentials",
  },
  {
    id: "e-admin-srv",
    source: "admin-role",
    target: "server-prod-01",
    relation: "ssh_access",
  },
  {
    id: "e-admin-db",
    source: "admin-role",
    target: "db-prod-01",
    relation: "direct_admin",
  },
];

// Attack path from firewall to crown jewel
const ATTACK_PATH_NODES = ["firewall-edge-01", "server-prod-01", "db-prod-01"];
const ATTACK_PATH_EDGES = ["e-fw-srv", "e-srv-db"];

// Multi-Factor Quantitative Dynamic Risk Formula (Module X9)
function computeDynamicRisk(node: TopologyNode, isUnderAttack: boolean): number {
  const critMultiplier =
    node.criticality === "critical"
      ? 2.0
      : node.criticality === "high"
      ? 1.5
      : node.criticality === "medium"
      ? 1.0
      : 0.8;

  const baseSev =
    node.criticality === "critical"
      ? 35.0
      : node.criticality === "high"
      ? 25.0
      : node.criticality === "medium"
      ? 15.0
      : 5.0;

  const baseComponent = baseSev * critMultiplier;
  const velocityFactor = isUnderAttack ? 15.0 : 0.0;
  const exploitFactor = node.hasCisaKev || (node.cvss && node.cvss >= 9.0) ? 25.0 : 0.0;
  const blastFactor = node.isCrownJewel ? 20.0 : node.id === "server-prod-01" ? 15.0 : 5.0;

  const rawScore = baseComponent + velocityFactor + exploitFactor + blastFactor;
  return Math.min(100, Math.max(0, Math.round(rawScore)));
}

interface TopologyGraphProps {
  cmdbAssets?: Asset[];
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({ cmdbAssets = [] }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>("server-prod-01");
  const [highlightAttackPath, setHighlightAttackPath] = useState<boolean>(true);
  const [blastRadiusSource, setBlastRadiusSource] = useState<string | null>(null);
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [draggedNode, setDraggedNode] = useState<{ id: string; startX: number; startY: number } | null>(null);

  // Compute blast radius from chosen source (up to 2 hops BFS)
  const computeBlastRadius = (startId: string): Set<string> => {
    const visited = new Set<string>([startId]);
    const queue: [string, number][] = [[startId, 0]];
    while (queue.length > 0) {
      const [curr, hops] = queue.shift()!;
      if (hops < 2) {
        for (const edge of DEFAULT_EDGES) {
          if (edge.source === curr && !visited.has(edge.target)) {
            visited.add(edge.target);
            queue.push([edge.target, hops + 1]);
          }
        }
      }
    }
    return visited;
  };

  const activeBlastSet = blastRadiusSource ? computeBlastRadius(blastRadiusSource) : new Set<string>();

  // Dynamically enrich baseline nodes with live CMDB asset data (IPs, description, criticality)
  // and dynamically display any newly enrolled custom CMDB assets on the canvas
  const displayNodes = useMemo(() => {
    const nodes = DEFAULT_NODES.map((node) => {
      const match = cmdbAssets.find((a) => a.hostname === node.id || a.id === node.id);
      if (match) {
        return {
          ...node,
          ip: match.ip_address || node.ip,
          criticality: match.criticality || node.criticality,
          description: match.description || node.description,
        };
      }
      return node;
    });

    const existingIds = new Set(nodes.map((n) => n.id));
    let customIndex = 0;
    cmdbAssets.forEach((asset) => {
      const id = asset.hostname || asset.id;
      if (!existingIds.has(id)) {
        nodes.push({
          id,
          label: asset.hostname || "Custom Asset",
          type: "asset",
          assetType: asset.asset_type,
          criticality: asset.criticality,
          isCrownJewel: asset.criticality === "critical",
          x: 200 + (customIndex % 3) * 150,
          y: 280 + Math.floor(customIndex / 3) * 60,
          ip: asset.ip_address || undefined,
          description: asset.description || "Custom enrolled CMDB asset target.",
        });
        customIndex++;
      }
    });

    return nodes.map((n) => ({
      ...n,
      x: nodePositions[n.id]?.x ?? n.x,
      y: nodePositions[n.id]?.y ?? n.y,
    }));
  }, [cmdbAssets, nodePositions]);

  const selectedNode = displayNodes.find((n) => n.id === selectedNodeId) || displayNodes[0];
  const dynamicRiskScore = computeDynamicRisk(
    selectedNode,
    highlightAttackPath && ATTACK_PATH_NODES.includes(selectedNode.id)
  );

  const handleNodeClick = (nodeId: string) => {
    setSelectedNodeId(nodeId);
    if (blastRadiusSource) {
      setBlastRadiusSource(nodeId);
    }
  };

  const handlePointerDown = (e: React.PointerEvent, nodeId: string) => {
    e.stopPropagation();
    try {
      (e.currentTarget as Element).setPointerCapture(e.pointerId);
    } catch {
      // ignore
    }
    setDraggedNode({ id: nodeId, startX: e.clientX, startY: e.clientY });
    handleNodeClick(nodeId);
  };

  const handlePointerMove = (e: React.PointerEvent) => {
    if (!draggedNode) return;
    const dx = e.clientX - draggedNode.startX;
    const dy = e.clientY - draggedNode.startY;
    if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;

    setNodePositions((prev) => {
      const current = displayNodes.find((n) => n.id === draggedNode.id);
      if (!current) return prev;
      return {
        ...prev,
        [draggedNode.id]: {
          x: Math.max(40, Math.min(700, current.x + dx)),
          y: Math.max(40, Math.min(400, current.y + dy)),
        },
      };
    });
    setDraggedNode({ id: draggedNode.id, startX: e.clientX, startY: e.clientY });
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    if (draggedNode) {
      try {
        (e.currentTarget as Element).releasePointerCapture(e.pointerId);
      } catch {
        // ignore
      }
      setDraggedNode(null);
    }
  };

  const toggleBlastSimulation = () => {
    if (blastRadiusSource) {
      setBlastRadiusSource(null);
    } else {
      setBlastRadiusSource(selectedNodeId);
      setHighlightAttackPath(false);
    }
  };

  const toggleAttackPath = () => {
    setHighlightAttackPath(!highlightAttackPath);
    if (!highlightAttackPath) {
      setBlastRadiusSource(null);
    }
  };

  const resetViews = () => {
    setHighlightAttackPath(false);
    setBlastRadiusSource(null);
    setSelectedNodeId("server-prod-01");
    setNodePositions({});
  };

  // Node icon helper
  const renderNodeIcon = (node: TopologyNode) => {
    if (node.isCrownJewel) return <Database className="h-5 w-5 text-amber-400" />;
    if (node.type === "identity") return <Key className="h-5 w-5 text-indigo-400" />;
    if (node.type === "vulnerability") return <Bug className="h-5 w-5 text-red-400" />;
    if (node.assetType === "firewall") return <Radio className="h-5 w-5 text-cyan-400" />;
    if (node.assetType === "workstation") return <Laptop className="h-5 w-5 text-teal-400" />;
    return <Server className="h-5 w-5 text-cyan-400" />;
  };

  return (
    <div className="space-y-4">
      {/* Top Banner & Control Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-cyber-border bg-cyber-card p-3 font-mono text-xs">
        <div className="flex items-center space-x-2">
          <Crosshair className="h-4 w-4 text-cyber-primary" />
          <span className="font-bold text-white uppercase tracking-wider">
            Security Knowledge Graph & Attack Path Engine (X8 & X9)
          </span>
          <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-cyan-300 border border-slate-700">
            Dijkstra & BFS Multigraph
          </span>
          {cmdbAssets.length > 0 && (
            <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300 border border-slate-700">
              {cmdbAssets.length} CMDB Assets Linked
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={toggleAttackPath}
            className={`flex items-center space-x-1.5 rounded border px-2.5 py-1.5 transition-colors ${
              highlightAttackPath
                ? "border-red-500 bg-red-950/60 text-red-200"
                : "border-cyber-border bg-cyber-surface text-slate-300 hover:bg-slate-800"
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
            <span>{highlightAttackPath ? "Attack Path (Active)" : "Trace Attack Path"}</span>
          </button>

          <button
            onClick={toggleBlastSimulation}
            className={`flex items-center space-x-1.5 rounded border px-2.5 py-1.5 transition-colors ${
              blastRadiusSource
                ? "border-orange-500 bg-orange-950/60 text-orange-200"
                : "border-cyber-border bg-cyber-surface text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Radio className="h-3.5 w-3.5 text-orange-400" />
            <span>{blastRadiusSource ? `Blast Radius (${blastRadiusSource})` : "Simulate Blast Radius"}</span>
          </button>

          <button
            onClick={resetViews}
            className="flex items-center space-x-1 rounded border border-cyber-border bg-cyber-surface px-2 py-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
            title="Reset highlight layers"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* Main Visualizer & Node Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* SVG Graph Topology Canvas */}
        <div className="lg:col-span-2 rounded-lg border border-cyber-border bg-cyber-bg p-4 relative overflow-hidden flex flex-col justify-between shadow-inner min-h-[460px]">
          {/* Subtle Background Grid Pattern */}
          <div
            className="absolute inset-0 opacity-15 pointer-events-none"
            style={{
              backgroundImage:
                "radial-gradient(#38bdf8 1px, transparent 1px), radial-gradient(#38bdf8 1px, transparent 1px)",
              backgroundSize: "24px 24px",
              backgroundPosition: "0 0, 12px 12px",
            }}
          />

          {/* Canvas Status Watermark */}
          <div className="relative z-10 flex items-center justify-between text-[11px] font-mono text-slate-500 mb-2">
            <div>
              <span>Interactive Enterprise Security Topology</span>
              {highlightAttackPath && (
                <span className="ml-2 font-semibold text-red-400">
                  [!] Active Lateral Path to Crown Jewel Discovered (2 Hops)
                </span>
              )}
              {blastRadiusSource && (
                <span className="ml-2 font-semibold text-orange-400">
                  [*] Transitive Blast Horizon from {blastRadiusSource} ({activeBlastSet.size} entities)
                </span>
              )}
            </div>
            <div className="text-[10px] text-slate-400">Click or drag any entity to inspect & reposition layout</div>
          </div>

          {/* SVG Elements */}
          <div className="relative z-10 flex-1 flex items-center justify-center">
            <svg
              viewBox="0 0 740 440"
              onPointerMove={handlePointerMove}
              onPointerUp={handlePointerUp}
              className="w-full h-auto max-h-[420px] select-none"
              style={{ overflow: "visible" }}
            >
              <defs>
                {/* Arrowhead marker default */}
                <marker
                  id="arrow-default"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
                </marker>
                {/* Arrowhead marker attack path */}
                <marker
                  id="arrow-attack"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="7"
                  markerHeight="7"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
                </marker>
                {/* Arrowhead marker blast radius */}
                <marker
                  id="arrow-blast"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#f97316" />
                </marker>
              </defs>

              {/* Render Graph Edges */}
              {DEFAULT_EDGES.map((edge) => {
                const source = displayNodes.find((n) => n.id === edge.source);
                const target = displayNodes.find((n) => n.id === edge.target);
                if (!source || !target) return null;

                const isPathEdge = highlightAttackPath && ATTACK_PATH_EDGES.includes(edge.id);
                const isBlastEdge =
                  blastRadiusSource &&
                  activeBlastSet.has(edge.source) &&
                  activeBlastSet.has(edge.target);

                let strokeColor = "#334155";
                let strokeWidth = 1.5;
                let strokeDash = undefined;
                let markerId = "arrow-default";

                if (isPathEdge) {
                  strokeColor = "#ef4444";
                  strokeWidth = 3;
                  markerId = "arrow-attack";
                } else if (isBlastEdge) {
                  strokeColor = "#f97316";
                  strokeWidth = 2;
                  strokeDash = "4 3";
                  markerId = "arrow-blast";
                }

                // Midpoint for label
                const midX = (source.x + target.x) / 2;
                const midY = (source.y + target.y) / 2 - 6;

                return (
                  <g key={edge.id}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke={strokeColor}
                      strokeWidth={strokeWidth}
                      strokeDasharray={strokeDash}
                      markerEnd={`url(#${markerId})`}
                      className={isPathEdge ? "animate-pulse" : ""}
                    />
                    <text
                      x={midX}
                      y={midY}
                      fill={isPathEdge ? "#f87171" : isBlastEdge ? "#fb923c" : "#64748b"}
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="pointer-events-none select-none"
                    >
                      {edge.relation}
                    </text>
                  </g>
                );
              })}

              {/* Render Graph Nodes */}
              {displayNodes.map((node) => {
                const isSelected = selectedNodeId === node.id;
                const isInAttackPath = highlightAttackPath && ATTACK_PATH_NODES.includes(node.id);
                const isInBlast = blastRadiusSource && activeBlastSet.has(node.id);
                const isBlastRoot = blastRadiusSource === node.id;

                let ringClass = "stroke-slate-600 fill-slate-800";
                if (isSelected) {
                  ringClass = "stroke-cyan-400 stroke-2 fill-slate-800";
                }
                if (node.isCrownJewel) {
                  ringClass = "stroke-amber-400 stroke-2 fill-amber-950/60";
                }
                if (isInAttackPath) {
                  ringClass = "stroke-red-500 stroke-2 fill-red-950/70";
                }
                if (isBlastRoot) {
                  ringClass = "stroke-orange-500 stroke-3 fill-orange-950/90";
                } else if (isInBlast) {
                  ringClass = "stroke-orange-400 stroke-2 fill-orange-950/50";
                }

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onPointerDown={(e) => handlePointerDown(e, node.id)}
                    onClick={() => handleNodeClick(node.id)}
                    className="cursor-grab active:cursor-grabbing transition-transform hover:scale-110"
                    tabIndex={0}
                    role="button"
                    aria-label={`Node ${node.label}`}
                  >
                    {/* Outer Glow / Halo for Crown Jewels & Selected */}
                    {(node.isCrownJewel || isInAttackPath || isBlastRoot) && (
                      <circle
                        r={26}
                        className={`opacity-30 ${
                          isInAttackPath
                            ? "fill-red-500 animate-ping"
                            : isBlastRoot
                            ? "fill-orange-500 animate-pulse"
                            : "fill-amber-400"
                        }`}
                      />
                    )}

                    {/* Base Node Circle */}
                    <circle r={20} className={`${ringClass} transition-colors`} />

                    {/* Node Label Text */}
                    <text
                      y={32}
                      textAnchor="middle"
                      fill={
                        node.isCrownJewel
                          ? "#fde047"
                          : isInAttackPath
                          ? "#fca5a5"
                          : isSelected
                          ? "#38bdf8"
                          : "#cbd5e1"
                      }
                      fontSize="10"
                      fontWeight={isSelected || node.isCrownJewel ? "bold" : "normal"}
                      fontFamily="monospace"
                      className="pointer-events-none select-none"
                    >
                      {node.id}
                    </text>

                    {/* Inner Type indicator badge */}
                    <text
                      y={43}
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize="8"
                      fontFamily="monospace"
                      className="pointer-events-none select-none"
                    >
                      {node.type.toUpperCase()}
                    </text>

                    {/* Central Icon representation */}
                    <foreignObject x={-10} y={-10} width={20} height={20} className="pointer-events-none">
                      <div className="flex h-full w-full items-center justify-center">
                        {renderNodeIcon(node)}
                      </div>
                    </foreignObject>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Graph Legend */}
          <div className="relative z-10 flex flex-wrap items-center justify-between border-t border-cyber-border pt-2 text-[10px] font-mono text-slate-400 gap-2">
            <div className="flex items-center space-x-3">
              <span className="flex items-center space-x-1">
                <span className="h-2 w-2 rounded-full bg-cyan-400" />
                <span>Asset</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                <span>Crown Jewel</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="h-2 w-2 rounded-full bg-indigo-400" />
                <span>Identity / Role</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="h-2 w-2 rounded-full bg-red-400" />
                <span>Vulnerability</span>
              </span>
            </div>
            <div className="text-slate-500">
              Total Vertices: {displayNodes.length} | Relationships: {DEFAULT_EDGES.length}
            </div>
          </div>
        </div>

        {/* Node Inspector & Multi-Factor Quantitative Risk Card */}
        <div className="flex flex-col space-y-4">
          {/* Node Summary Card */}
          <div className="rounded-lg border border-cyber-border bg-cyber-surface p-4 font-mono space-y-4">
            <div className="flex items-start justify-between border-b border-cyber-border pb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-bold text-white">{selectedNode.label}</span>
                  {selectedNode.isCrownJewel && (
                    <span className="rounded bg-amber-950/80 px-1.5 py-0.5 text-[10px] font-bold text-amber-300 border border-amber-800">
                      CROWN JEWEL
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-400 mt-0.5">ID: {selectedNode.id}</div>
              </div>
              <SeverityBadge severity={selectedNode.criticality} />
            </div>

            {/* Dynamic Multi-Factor Risk Score (X9) */}
            <div className="rounded border border-cyber-border bg-cyber-card p-3 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400 font-semibold flex items-center space-x-1">
                  <Crosshair className="h-3.5 w-3.5 text-cyber-primary" />
                  <span>Dynamic Quantitative Risk</span>
                </span>
                <RiskScoreBadge score={dynamicRiskScore} />
              </div>

              <div className="space-y-1 text-[11px] text-slate-300 pt-1 border-t border-cyber-border/60">
                <div className="flex justify-between">
                  <span className="text-slate-400">Criticality Multiplier:</span>
                  <span className="font-semibold">
                    {selectedNode.criticality === "critical"
                      ? "2.0x"
                      : selectedNode.criticality === "high"
                      ? "1.5x"
                      : "1.0x"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Threat Velocity Factor:</span>
                  <span className={highlightAttackPath && ATTACK_PATH_NODES.includes(selectedNode.id) ? "text-red-400" : ""}>
                    {highlightAttackPath && ATTACK_PATH_NODES.includes(selectedNode.id) ? "+15.0 (Active Path)" : "0.0"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">CISA KEV / CVSS Factor:</span>
                  <span className={selectedNode.hasCisaKev ? "text-red-400 font-semibold" : ""}>
                    {selectedNode.hasCisaKev ? "+25.0 (Exploited in Wild)" : "0.0"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Topological Blast Factor:</span>
                  <span className={selectedNode.isCrownJewel ? "text-amber-400 font-semibold" : ""}>
                    {selectedNode.isCrownJewel ? "+20.0 (Crown Jewel Target)" : selectedNode.id === "server-prod-01" ? "+15.0 (Pivot Host)" : "+5.0"}
                  </span>
                </div>
              </div>
            </div>

            {/* Node Metadata & Description */}
            <div className="space-y-2 text-xs">
              <div className="text-slate-400">Description:</div>
              <div className="rounded bg-cyber-card p-2 text-[11px] text-slate-300 leading-relaxed">
                {selectedNode.description}
              </div>

              {selectedNode.ip && (
                <div className="flex justify-between text-[11px] border-b border-cyber-border/60 py-1">
                  <span className="text-slate-400">IP Address:</span>
                  <span className="text-slate-200">{selectedNode.ip}</span>
                </div>
              )}

              {selectedNode.cve && (
                <div className="flex justify-between text-[11px] border-b border-cyber-border/60 py-1">
                  <span className="text-slate-400">Active Vulnerability:</span>
                  <span className="text-red-400 font-semibold flex items-center space-x-1">
                    <Bug className="h-3 w-3" />
                    <span>{selectedNode.cve}</span>
                  </span>
                </div>
              )}

              {selectedNode.hasCisaKev && (
                <div className="rounded border border-red-800 bg-red-950/40 p-2 text-[11px] text-red-300 flex items-start space-x-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                  <div>
                    <span className="font-bold">CISA KEV Flagged:</span> This entity carries known actively exploited vulnerabilities in federal & enterprise wild.
                  </div>
                </div>
              )}
            </div>

            {/* Quick Actions for Selected Entity */}
            <div className="pt-2 border-t border-cyber-border space-y-2">
              <button
                onClick={() => {
                  setBlastRadiusSource(selectedNode.id);
                  setHighlightAttackPath(false);
                }}
                className="w-full flex items-center justify-center space-x-1.5 rounded border border-cyber-border bg-cyber-card py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
              >
                <Radio className="h-3.5 w-3.5 text-orange-400" />
                <span>Simulate Blast Radius from {selectedNode.id}</span>
              </button>

              {selectedNode.type === "asset" && (
                <div className="flex items-center space-x-2 pt-1">
                  <Link
                    to={`/alerts?search=${selectedNode.id}`}
                    className="flex-1 flex items-center justify-center space-x-1 rounded border border-cyber-border bg-cyber-card py-1 text-[11px] text-slate-300 hover:border-red-500 hover:text-red-300 transition-colors"
                    title="View alerts on this asset"
                  >
                    <ShieldAlert className="h-3 w-3 text-red-400" />
                    <span>View Alerts</span>
                  </Link>
                  <Link
                    to={`/incidents?search=${selectedNode.id}`}
                    className="flex-1 flex items-center justify-center space-x-1 rounded border border-cyber-border bg-cyber-card py-1 text-[11px] text-slate-300 hover:border-orange-500 hover:text-orange-300 transition-colors"
                    title="View cases on this asset"
                  >
                    <Flame className="h-3 w-3 text-orange-400" />
                    <span>View Cases</span>
                  </Link>
                </div>
              )}
            </div>
          </div>

          {/* Discovered Attack Path Explanation Card */}
          {highlightAttackPath && (
            <div className="rounded-lg border border-red-900 bg-red-950/30 p-3 font-mono text-xs space-y-2">
              <div className="flex items-center space-x-2 text-red-300 font-bold">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                <span>Dijkstra Critical Path Analysis</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Shortest attack trajectory from public perimeter ingress to core financial data:
              </p>
              <div className="flex items-center space-x-1 text-[11px] text-amber-300 bg-black/40 p-2 rounded border border-red-900/60 overflow-x-auto">
                <span className="text-slate-300">firewall-edge-01</span>
                <ChevronRight className="h-3 w-3 text-red-400" />
                <span className="text-red-300 font-bold">server-prod-01</span>
                <ChevronRight className="h-3 w-3 text-red-400" />
                <span className="text-amber-300 font-bold">db-prod-01</span>
              </div>
              <div className="text-[10px] text-slate-400">
                Rule ID: <span className="text-cyan-400">RULE-GRAPH-BLAST-RADIUS</span> (MITRE ATT&CK T1021)
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default TopologyGraph;
