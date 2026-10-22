import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { SimulationModal } from "../components/SimulationModal";
import { ToastProvider } from "../context/ToastContext";
import { eventsApi } from "../services/api";

vi.mock("../services/api", () => ({
  eventsApi: {
    ingestBatch: vi.fn(),
    ingestSingle: vi.fn(),
  },
}));

const renderModal = (isOpen = true, onClose = vi.fn()) => {
  return render(
    <ToastProvider>
      <BrowserRouter>
        <SimulationModal isOpen={isOpen} onClose={onClose} />
      </BrowserRouter>
    </ToastProvider>
  );
};

describe("SimulationModal Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("does not render when isOpen is false", () => {
    renderModal(false);
    expect(screen.queryByText(/Red Team Attack Simulator/i)).not.toBeInTheDocument();
  });

  it("renders scenario list and details when open", () => {
    renderModal(true);
    expect(screen.getByText(/Red Team Attack Simulator & Scenario Lab/i)).toBeInTheDocument();
    expect(screen.getAllByText("SSH Brute-Force Credential Stuffing").length).toBeGreaterThan(0);
    expect(screen.getByText("TCP SYN Reconnaissance Port Sweep")).toBeInTheDocument();
    expect(screen.getByText("SQL Injection Data Exfiltration")).toBeInTheDocument();
    expect(screen.getByText("High-Entropy DNS Tunneling Exfiltration")).toBeInTheDocument();
    expect(screen.getByText("Critical System File Tampering (FIM)")).toBeInTheDocument();
    expect(screen.getByText("Full Multi-Stage APT Intrusion Campaign")).toBeInTheDocument();
  });

  it("switches scenario when clicking another scenario item", () => {
    renderModal(true);
    const sqliButton = screen.getByText("SQL Injection Data Exfiltration");
    fireEvent.click(sqliButton);

    expect(screen.getAllByText("RULE-WEB-001").length).toBeGreaterThan(0);
    expect(screen.getByText(/UNION SELECT/i)).toBeInTheDocument();
  });

  it("dispatches telemetry batch when Launch Attack Simulation is clicked", async () => {
    const mockResponse = {
      ingested_count: 6,
      event_ids: ["id-1", "id-2", "id-3", "id-4", "id-5", "id-6"],
      status: "success",
    };
    (eventsApi.ingestBatch as any).mockResolvedValueOnce(mockResponse);

    renderModal(true);

    const launchButton = screen.getByRole("button", { name: /Launch Attack Simulation/i });
    fireEvent.click(launchButton);

    await waitFor(() => {
      expect(eventsApi.ingestBatch).toHaveBeenCalledTimes(1);
    });

    expect(await screen.findByText(/Simulation Successfully Ingested!/i)).toBeInTheDocument();
    expect(screen.getByText(/View Alerts Queue/i)).toBeInTheDocument();
  });
});
