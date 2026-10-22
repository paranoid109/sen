import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { SOARPlaybookModal } from "../components/SOARPlaybookModal";
import { ToastProvider } from "../context/ToastContext";
import { incidentsApi } from "../services/api";
import type { IncidentDetail } from "../types";

vi.mock("../services/api", () => ({
  incidentsApi: {
    addTimelineEntry: vi.fn(),
  },
}));

const mockIncident: IncidentDetail = {
  id: "inc-test-uuid-1234",
  title: "Multi-Stage Attack on srv-app-01: T1046 -> T1190",
  description: "Correlated multi-stage attack campaign across 2 alerts.",
  severity: "critical",
  status: "OPEN",
  risk_score: 95,
  target_asset_id: "asset-1",
  target_host: "srv-app-01",
  alerts: [
    {
      id: "alert-1",
      rule_id: "RULE-NET-001",
      rule_name: "TCP Port Scan",
      severity: "high",
      status: "NEW",
      mitre_attack_id: "T1046",
      source_ip: "203.0.113.88",
      target_asset_id: "asset-1",
      target_host: "srv-app-01",
      dedup_key: "hash123",
      occurrence_count: 10,
      first_seen: "2026-10-20T00:00:00Z",
      last_seen: "2026-10-20T00:05:00Z",
      evidence: [],
      created_at: "2026-10-20T00:00:00Z",
      updated_at: "2026-10-20T00:05:00Z",
    },
  ],
  timeline: [],
  created_at: "2026-10-20T00:00:00Z",
  updated_at: "2026-10-20T00:05:00Z",
};

const renderWithProviders = (ui: React.ReactElement) => {
  return render(
    <ToastProvider>
      <BrowserRouter>{ui}</BrowserRouter>
    </ToastProvider>
  );
};

describe("SOARPlaybookModal Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders all 4 playbook tabs and incident context when open", () => {
    renderWithProviders(
      <SOARPlaybookModal
        incident={mockIncident}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText(/SOAR Containment & Digital Forensics/i)).toBeInTheDocument();
    expect(screen.getByText(/1\. Network IP Block/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Endpoint Quarantine/i)).toBeInTheDocument();
    expect(screen.getByText(/3\. Identity Suspension/i)).toBeInTheDocument();
    expect(screen.getByText(/4\. Digital Forensics Triage/i)).toBeInTheDocument();
    expect(screen.getByText(/Playbook Directive Preview/i)).toBeInTheDocument();
  });

  it("triggers safety guardrail when protected gateway IP 192.168.1.1 is targeted", () => {
    renderWithProviders(
      <SOARPlaybookModal
        incident={mockIncident}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    const ipInput = screen.getByLabelText(/Target Attacker IP Address:/i);
    fireEvent.change(ipInput, { target: { value: "192.168.1.1" } });

    expect(screen.getByText(/Safety Guardrail Triggered/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Execute & Record Containment/i })).toBeDisabled();
  });

  it("switches to Endpoint Quarantine tab and displays isolation commands", () => {
    renderWithProviders(
      <SOARPlaybookModal
        incident={mockIncident}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    fireEvent.click(screen.getByText(/2\. Endpoint Quarantine/i));
    expect(screen.getByLabelText(/Target Endpoint Hostname:/i)).toHaveValue("srv-app-01");
    expect(screen.getByText(/Quarantine Directive for Host: srv-app-01/i)).toBeInTheDocument();
    expect(screen.getByText(/Preserves SentinelX agent telemetry/i)).toBeInTheDocument();
  });

  it("switches to Identity Suspension tab and triggers guardrail warning on root account", () => {
    renderWithProviders(
      <SOARPlaybookModal
        incident={mockIncident}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    fireEvent.click(screen.getByText(/3\. Identity Suspension/i));
    const userInput = screen.getByLabelText(/Compromised Account Username:/i);
    fireEvent.change(userInput, { target: { value: "root" } });

    expect(screen.getByText(/Administrative Guardrail Triggered/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Execute & Record Containment/i })).toBeDisabled();
  });

  it("switches to Digital Forensics tab, shows Root SHA-256 seal and exports package", () => {
    renderWithProviders(
      <SOARPlaybookModal
        incident={mockIncident}
        isOpen={true}
        onClose={vi.fn()}
      />
    );

    fireEvent.click(screen.getByText(/4\. Digital Forensics Triage/i));
    expect(screen.getByText(/Evidence Chain of Custody/i)).toBeInTheDocument();
    expect(screen.getByText(/Status: VERIFIED/i)).toBeInTheDocument();
    expect(screen.getByText(/0e08742a74adf6f9b8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4/i)).toBeInTheDocument();
    expect(screen.getByText(/Export Sealed Package JSON/i)).toBeInTheDocument();
  });

  it("executes valid network IP containment and records to incident timeline", async () => {
    const onActionExecuted = vi.fn();
    vi.mocked(incidentsApi.addTimelineEntry).mockResolvedValueOnce({
      id: "timeline-123",
      timestamp: "2026-10-20T02:00:00Z",
      event_type: "soar_containment_executed",
      description: "[SOAR] Executed Network IP Containment on 203.0.113.88",
      source: "SOAR_Engine",
    });

    renderWithProviders(
      <SOARPlaybookModal
        incident={mockIncident}
        isOpen={true}
        onClose={vi.fn()}
        onActionExecuted={onActionExecuted}
      />
    );

    const execBtn = screen.getByText(/Execute & Record Containment/i);
    expect(execBtn).not.toBeDisabled();
    fireEvent.click(execBtn);

    await waitFor(() => {
      expect(incidentsApi.addTimelineEntry).toHaveBeenCalledWith(
        "inc-test-uuid-1234",
        expect.objectContaining({
          event_type: "soar_containment_executed",
          source: "SOAR_Engine",
        })
      );
    });

    expect(screen.getByText(/Containment Directive Active & Committed/i)).toBeInTheDocument();
    expect(onActionExecuted).toHaveBeenCalled();
  });
});
