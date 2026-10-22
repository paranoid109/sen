import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { CloudSecurity } from "../pages/CloudSecurity";
import { ToastProvider } from "../context/ToastContext";

const renderPage = () => {
  return render(
    <ToastProvider>
      <BrowserRouter>
        <CloudSecurity />
      </BrowserRouter>
    </ToastProvider>
  );
};

describe("CloudSecurity Component (Module X12)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders page header and multi-cloud posture KPI banner", () => {
    renderPage();
    expect(screen.getByText(/Cloud Security Posture Management \(CSPM\)/i)).toBeInTheDocument();
    expect(screen.getByText("Module X12")).toBeInTheDocument();
    expect(screen.getByText(/CIS Compliance Score/i)).toBeInTheDocument();
    expect(screen.getByText(/Active Misconfigurations/i)).toBeInTheDocument();
    expect(screen.getByText(/Critical Exposures/i)).toBeInTheDocument();
  });

  it("renders default cloud findings list across AWS, GCP, and Azure", () => {
    renderPage();
    expect(screen.getByText("CIS-AWS-2.1.1")).toBeInTheDocument();
    expect(screen.getByText("CIS-GCP-1.1")).toBeInTheDocument();
    expect(screen.getByText("CIS-AZURE-3.1")).toBeInTheDocument();
    expect(screen.getByText("aws:s3:::finance-confidential-backups")).toBeInTheDocument();
  });

  it("filters findings by cloud provider", () => {
    renderPage();
    const providerSelect = screen.getByDisplayValue("All Providers");
    fireEvent.change(providerSelect, { target: { value: "aws" } });

    expect(screen.getByText("CIS-AWS-2.1.1")).toBeInTheDocument();
    expect(screen.queryByText("CIS-GCP-1.1")).not.toBeInTheDocument();
    expect(screen.queryByText("CIS-AZURE-3.1")).not.toBeInTheDocument();
  });

  it("filters findings by search query", () => {
    renderPage();
    const searchInput = screen.getByPlaceholderText(/Search target resource/i);
    fireEvent.change(searchInput, { target: { value: "finance-confidential" } });

    expect(screen.getByText("aws:s3:::finance-confidential-backups")).toBeInTheDocument();
    expect(screen.queryByText("gcp:storage://gcs-customer-pii-data")).not.toBeInTheDocument();
  });

  it("expands remediation guidance when a finding card is clicked", () => {
    renderPage();
    const findingCard = screen.getByText("aws:s3:::finance-confidential-backups");
    fireEvent.click(findingCard);

    expect(screen.getByText(/CIS Remediation Guidance/i)).toBeInTheDocument();
    expect(screen.getByText(/Enable S3 Public Access Block at account and bucket level/i)).toBeInTheDocument();
  });

  it("triggers audit scan and updates state when Run Multi-Cloud Scan is clicked", async () => {
    renderPage();
    const scanButton = screen.getByRole("button", { name: /Run Multi-Cloud Scan/i });
    fireEvent.click(scanButton);

    expect(screen.getByText(/Auditing Control Planes.../i)).toBeInTheDocument();

    await waitFor(
      () => {
        expect(screen.getByRole("button", { name: /Run Multi-Cloud Scan/i })).toBeInTheDocument();
      },
      { timeout: 2000 }
    );
  });
});
