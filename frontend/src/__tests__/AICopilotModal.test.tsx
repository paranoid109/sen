import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { AICopilotModal } from "../components/AICopilotModal";
import { ToastProvider } from "../context/ToastContext";
import { IncidentDetail } from "../types";

const mockIncident: IncidentDetail = {
  id: "inc-1001",
  title: "Multi-Stage SQL Injection & Reverse Shell",
  description: "Attacker performed SQL injection against db-prod-01 followed by shell execution",
  severity: "critical",
  status: "OPEN",
  risk_score: 92,
  target_asset_id: "asset-1",
  target_host: "db-prod-01",
  alerts: [],
  timeline: [],
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const renderModal = (isOpen = true, onClose = vi.fn(), incident = mockIncident) => {
  return render(
    <ToastProvider>
      <BrowserRouter>
        <AICopilotModal
          isOpen={isOpen}
          onClose={onClose}
          incident={incident}
        />
      </BrowserRouter>
    </ToastProvider>
  );
};

describe("AICopilotModal Component (Module X13)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("does not render when isOpen is false", () => {
    renderModal(false);
    expect(screen.queryByText(/SentinelX AI SOC Analyst Copilot/i)).not.toBeInTheDocument();
  });

  it("renders when open and displays Executive Briefing by default", () => {
    renderModal(true);
    expect(screen.getByText(/SentinelX AI SOC Analyst Copilot/i)).toBeInTheDocument();
    expect(screen.getByText("Module X13")).toBeInTheDocument();
    expect(screen.getByText(/1. Executive Summary & Impact Analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/2. Root Cause Hypothesis/i)).toBeInTheDocument();
    expect(screen.getByText(/3. MITRE ATT&CK Kill-Chain Progression/i)).toBeInTheDocument();
    expect(screen.getByText(/4. Immediate Defensive Guidance/i)).toBeInTheDocument();
    expect(screen.getAllByText("host_quarantine").length).toBeGreaterThan(0);
  });

  it("switches to Alert Triage Advisor tab and displays verdict with confidence meter", () => {
    renderModal(true);
    const triageTab = screen.getByRole("button", { name: /Alert Triage Advisor/i });
    fireEvent.click(triageTab);

    expect(screen.getByText(/VERDICT: TRUE_POSITIVE \(98% Confidence\)/i)).toBeInTheDocument();
    expect(screen.getByText(/AI Confidence Score/i)).toBeInTheDocument();
    expect(screen.getByText(/Deterministic SQL injection signature match/i)).toBeInTheDocument();
    expect(screen.getByText(/Confirm True Positive & Escalate/i)).toBeInTheDocument();
  });

  it("switches to Natural Language Query tab and translates plain English prompt", () => {
    renderModal(true);
    const queryTab = screen.getByRole("button", { name: /Natural Language Query/i });
    fireEvent.click(queryTab);

    expect(screen.getByText(/Ask a question in plain English/i)).toBeInTheDocument();

    const input = screen.getByPlaceholderText(/e\.g\. Show critical alerts/i);
    fireEvent.change(input, { target: { value: "Show critical alerts for db-prod-01" } });

    const translateBtn = screen.getByRole("button", { name: /Translate/i });
    fireEvent.click(translateBtn);

    expect(screen.getByText(/Synthesized REST Query/i)).toBeInTheDocument();
    expect(screen.getByText(/GET \/api\/v1\/alerts/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Navigate & Apply Filter/i })).toBeInTheDocument();
  });

  it("copies briefing markdown to clipboard when Copy Markdown is clicked", () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    });

    renderModal(true);
    const copyBtn = screen.getByRole("button", { name: /Copy Markdown/i });
    fireEvent.click(copyBtn);

    expect(writeTextMock).toHaveBeenCalled();
  });
});
