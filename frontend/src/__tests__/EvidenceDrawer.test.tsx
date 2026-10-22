import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { EvidenceDrawer } from "../components/EvidenceDrawer";
import { ToastProvider } from "../context/ToastContext";
import { AuthContext } from "../context/AuthContext";
import type { Alert, User } from "../types";

const mockAlert: Alert = {
  id: "test-alert-uuid-1",
  rule_id: "RULE-AUTH-001",
  rule_name: "SSH Brute-Force Attempt",
  severity: "high",
  status: "NEW",
  mitre_attack_id: "T1110.001",
  source_ip: "192.168.1.150",
  target_asset_id: "asset-1",
  target_host: "server-prod-01",
  dedup_key: "abc123hash",
  occurrence_count: 5,
  first_seen: "2026-10-19T10:00:00Z",
  last_seen: "2026-10-19T10:05:00Z",
  evidence: [
    "Failed password for invalid user admin from 192.168.1.150 port 54122 ssh2",
    "Failed password for root from 192.168.1.150 port 54124 ssh2",
  ],
  created_at: "2026-10-19T10:00:00Z",
  updated_at: "2026-10-19T10:05:00Z",
};

const mockUser: User = {
  id: "user-1",
  username: "analyst_tester",
  email: "analyst@sentinelx.local",
  role: "Analyst",
  is_active: true,
  created_at: "2026-10-19T10:00:00Z",
};

const renderWithProviders = (ui: React.ReactElement) => {
  return render(
    <AuthContext.Provider
      value={{
        user: mockUser,
        token: "fake-jwt",
        login: vi.fn(),
        logout: vi.fn(),
        isLoading: false,
        hasRole: (roles) => roles.includes(mockUser.role),
      }}
    >
      <ToastProvider>
        <BrowserRouter>{ui}</BrowserRouter>
      </ToastProvider>
    </AuthContext.Provider>
  );
};

describe("EvidenceDrawer Component", () => {
  it("renders alert metadata, MITRE hyperlink, and formatted evidence lines", () => {
    const handleClose = vi.fn();
    renderWithProviders(
      <EvidenceDrawer alert={mockAlert} onClose={handleClose} />
    );

    // Rule name and ID
    expect(screen.getByText("SSH Brute-Force Attempt")).toBeInTheDocument();
    expect(screen.getByText("RULE-AUTH-001")).toBeInTheDocument();

    // Source IP and Target Host
    expect(screen.getByText("192.168.1.150")).toBeInTheDocument();
    expect(screen.getByText("server-prod-01")).toBeInTheDocument();

    // MITRE link
    const mitreLink = screen.getByText(/MITRE T1110.001/i).closest("a");
    expect(mitreLink).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1110/001/"
    );

    // Forensic evidence samples
    expect(
      screen.getByText(/Failed password for invalid user admin/i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Failed password for root/i)
    ).toBeInTheDocument();

    // Triage buttons for Analyst
    expect(screen.getByText("Commit Triage")).toBeInTheDocument();

    // Close button
    fireEvent.click(screen.getByTitle("Close drawer"));
    expect(handleClose).toHaveBeenCalledOnce();
  });
});
