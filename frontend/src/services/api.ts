import axios from "axios";
import type {
  Alert,
  AlertTriageRequest,
  ApiKey,
  ApiKeyCreated,
  Asset,
  AssetCreate,
  AuditLog,
  AuditVerify,
  DashboardMetrics,
  ExecutiveReport,
  Incident,
  IncidentDetail,
  IncidentTimelineItem,
  IncidentUpdateRequest,
  TokenResponse,
  User,
  BatchIngestRequest,
  SingleIngestRequest,
  IngestResponse,
} from "../types";

const API_BASE_URL = "/api/v1";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor: attach JWT token from sessionStorage
apiClient.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("sentinelx_token");
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: handle 401 unauthenticated
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      sessionStorage.removeItem("sentinelx_token");
      sessionStorage.removeItem("sentinelx_user");
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

// Auth & Users
export const authApi = {
  login: async (username: string, password: string): Promise<TokenResponse> => {
    const res = await apiClient.post<TokenResponse>("/auth/login", { username, password });
    return res.data;
  },
  getMe: async (): Promise<User> => {
    const res = await apiClient.get<User>("/auth/me");
    return res.data;
  },
  getUsers: async (): Promise<User[]> => {
    const res = await apiClient.get<User[]>("/auth/users");
    return res.data;
  },
  createUser: async (data: {
    username: string;
    email: string;
    password: string;
    role: "Admin" | "Analyst" | "Auditor";
  }): Promise<User> => {
    const res = await apiClient.post<User>("/auth/users", data);
    return res.data;
  },
  getApiKeys: async (): Promise<ApiKey[]> => {
    const res = await apiClient.get<ApiKey[]>("/auth/api-keys");
    return res.data;
  },
  createApiKey: async (data: {
    name: string;
    scope?: string;
    asset_id?: string | null;
  }): Promise<ApiKeyCreated> => {
    const res = await apiClient.post<ApiKeyCreated>("/auth/api-keys", data);
    return res.data;
  },
  deleteApiKey: async (keyId: string): Promise<{ message: string }> => {
    const res = await apiClient.delete<{ message: string }>(`/auth/api-keys/${keyId}`);
    return res.data;
  },
};

export interface AlertEvidenceEvent {
  id: string;
  event_time: string;
  event_type: string;
  source_ip: string;
  destination_ip?: string | null;
  destination_port?: number | null;
  target_host?: string | null;
  raw_payload?: string | null;
  details: Record<string, any>;
}

// Alerts (M5)
export const alertsApi = {
  getAlerts: async (params?: {
    status?: string;
    severity?: string;
    rule_id?: string;
    target_asset_id?: string;
    search?: string;
    skip?: number;
    limit?: number;
  }): Promise<Alert[]> => {
    const res = await apiClient.get<Alert[]>("/alerts", { params });
    return res.data;
  },
  getAlert: async (alertId: string): Promise<Alert> => {
    const res = await apiClient.get<Alert>(`/alerts/${alertId}`);
    return res.data;
  },
  getAlertEvents: async (alertId: string): Promise<AlertEvidenceEvent[]> => {
    const res = await apiClient.get<AlertEvidenceEvent[]>(`/alerts/${alertId}/events`);
    return res.data;
  },
  triageAlert: async (alertId: string, data: AlertTriageRequest): Promise<Alert> => {
    const res = await apiClient.patch<Alert>(`/alerts/${alertId}/triage`, data);
    return res.data;
  },
};

// Telemetry Ingestion (M3)
export const eventsApi = {
  ingestSingle: async (data: SingleIngestRequest): Promise<IngestResponse> => {
    const res = await apiClient.post<IngestResponse>("/events/ingest", data);
    return res.data;
  },
  ingestBatch: async (data: BatchIngestRequest): Promise<IngestResponse> => {
    const res = await apiClient.post<IngestResponse>("/events/batch", data);
    return res.data;
  },
};

// Incidents (M6)
export const incidentsApi = {
  getIncidents: async (params?: {
    status?: string;
    severity?: string;
    target_asset_id?: string;
    search?: string;
    skip?: number;
    limit?: number;
  }): Promise<Incident[]> => {
    const res = await apiClient.get<Incident[]>("/incidents", { params });
    return res.data;
  },
  getIncident: async (incidentId: string): Promise<IncidentDetail> => {
    const res = await apiClient.get<IncidentDetail>(`/incidents/${incidentId}`);
    return res.data;
  },
  updateIncident: async (
    incidentId: string,
    data: IncidentUpdateRequest
  ): Promise<IncidentDetail> => {
    const res = await apiClient.patch<IncidentDetail>(`/incidents/${incidentId}`, data);
    return res.data;
  },
  addTimelineEntry: async (
    incidentId: string,
    data: {
      event_type: string;
      description: string;
      source?: string;
      details?: Record<string, any>;
    }
  ): Promise<IncidentTimelineItem> => {
    const res = await apiClient.post<IncidentTimelineItem>(
      `/incidents/${incidentId}/timeline`,
      data
    );
    return res.data;
  },
};

// CMDB Assets (M2)
export const assetsApi = {
  getAssets: async (params?: { skip?: number; limit?: number }): Promise<Asset[]> => {
    const res = await apiClient.get<Asset[]>("/assets", { params });
    return res.data;
  },
  getAsset: async (assetId: string): Promise<Asset> => {
    const res = await apiClient.get<Asset>(`/assets/${assetId}`);
    return res.data;
  },
  createAsset: async (data: AssetCreate): Promise<Asset> => {
    const res = await apiClient.post<Asset>("/assets", data);
    return res.data;
  },
  updateAsset: async (assetId: string, data: Partial<AssetCreate>): Promise<Asset> => {
    const res = await apiClient.put<Asset>(`/assets/${assetId}`, data);
    return res.data;
  },
  deleteAsset: async (assetId: string): Promise<{ message: string }> => {
    const res = await apiClient.delete<{ message: string }>(`/assets/${assetId}`);
    return res.data;
  },
};

// Reports & Dashboard Metrics (M7)
export const reportsApi = {
  getMetrics: async (): Promise<DashboardMetrics> => {
    const res = await apiClient.get<DashboardMetrics>("/reports/metrics");
    return res.data;
  },
  getExecutiveReport: async (): Promise<ExecutiveReport> => {
    const res = await apiClient.get<ExecutiveReport>("/reports/executive");
    return res.data;
  },
};

// Tamper-Evident Audit Trail (Law 4)
export const auditApi = {
  getAuditLogs: async (params?: {
    action?: string;
    user_id?: string;
    skip?: number;
    limit?: number;
  }): Promise<AuditLog[]> => {
    const res = await apiClient.get<AuditLog[]>("/audit", { params });
    return res.data;
  },
  verifyAuditChain: async (): Promise<AuditVerify> => {
    const res = await apiClient.get<AuditVerify>("/audit/verify");
    return res.data;
  },
};
