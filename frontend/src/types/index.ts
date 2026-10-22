/**
 * SentinelX Frontend Contract Models & Type Definitions
 * Strict dual-sync with contracts/python/models.py and backend/app/schemas/ (Law 2)
 */

export type SeverityLevel = "critical" | "high" | "medium" | "low";

export type AlertStatus = "NEW" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";

export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "CLOSED";

export type UserRole = "Admin" | "Analyst" | "Auditor";

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  role: UserRole;
  username: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scope: string;
  asset_id: string | null;
  is_active: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface ApiKeyCreated {
  id: string;
  name: string;
  raw_key: string;
  prefix: string;
  scope: string;
  asset_id: string | null;
  created_at: string;
}

export interface Asset {
  id: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
  criticality: SeverityLevel;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetCreate {
  hostname?: string | null;
  ip_address?: string | null;
  asset_type?: string;
  criticality?: SeverityLevel;
  description?: string | null;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: SeverityLevel;
  status: AlertStatus;
  mitre_attack_id: string | null;
  source_ip: string;
  target_asset_id: string | null;
  target_host: string | null;
  dedup_key: string;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  evidence: string[];
  created_at: string;
  updated_at: string;
}

export interface AlertTriageRequest {
  status: AlertStatus;
  notes?: string | null;
}

export interface IncidentTimelineItem {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  source: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: SeverityLevel;
  status: IncidentStatus;
  risk_score: number;
  target_asset_id: string | null;
  target_host: string | null;
  alert_count: number;
  created_at: string;
  updated_at: string;
}

export interface IncidentDetail {
  id: string;
  title: string;
  description: string | null;
  severity: SeverityLevel;
  status: IncidentStatus;
  risk_score: number;
  target_asset_id: string | null;
  target_host: string | null;
  alerts: Alert[];
  timeline: IncidentTimelineItem[];
  created_at: string;
  updated_at: string;
}

export interface IncidentUpdateRequest {
  status?: IncidentStatus | null;
  description?: string | null;
  notes?: string | null;
}

export interface DashboardMetrics {
  total_events: number;
  active_alerts: number;
  open_incidents: number;
  monitored_assets: number;
  severity_breakdown: Record<string, number>;
  mttd_seconds: number | null;
}

export interface ExecutiveReport {
  generated_at: string;
  report_markdown: string;
  kpi_metrics: DashboardMetrics;
}

export interface AuditLog {
  id: string;
  sequence_number: number;
  timestamp: string;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  status: string;
  details: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditVerify {
  is_valid: boolean;
  total_records: number;
  error_message: string | null;
  broken_sequence: number | null;
}

export interface SingleIngestRequest {
  source_ip: string;
  destination_ip?: string | null;
  destination_port?: number | null;
  source_port?: number | null;
  event_type: string;
  target_host?: string | null;
  asset_id?: string | null;
  event_time?: string | null;
  raw_payload?: string | null;
  details?: Record<string, any>;
}

export interface BatchIngestRequest {
  events: SingleIngestRequest[];
  asset_id?: string | null;
  target_host?: string | null;
}

export interface IngestResponse {
  ingested_count: number;
  event_ids: string[];
  status: string;
}

export interface CloudFinding {
  finding_id: string;
  tool_name: string;
  rule_id: string;
  severity: SeverityLevel;
  target: string;
  description: string;
  benchmark_control: string;
  provider: "aws" | "gcp" | "azure" | "cloud";
  mitre_attack_id?: string;
  remediation?: string;
  timestamp: string;
}

export interface CloudPostureReport {
  total_records_analyzed: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  posture_score: number;
  findings_by_provider: Record<string, number>;
  findings: CloudFinding[];
}

export interface TriageAssessment {
  verdict: "TRUE_POSITIVE" | "FALSE_POSITIVE" | "SUSPICIOUS_NEED_MORE_INFO";
  confidence_score: number;
  reasoning: string[];
  suggested_action: string;
  recommended_status: AlertStatus;
}

export interface IncidentBriefing {
  incident_id: string;
  title: string;
  risk_score: number;
  severity: string;
  executive_summary: string;
  root_cause_hypothesis: string;
  kill_chain_narrative: string;
  mitre_mitigations: Array<{
    mitre_id: string;
    technique: string;
    cis_control: string;
    remediation: string;
  }>;
  recommended_playbooks: string[];
  markdown_content: string;
}

export interface QueryTranslation {
  natural_query: string;
  endpoint: string;
  method: string;
  params: Record<string, any>;
  explanation: string;
}

