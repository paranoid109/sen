import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { TopologyGraph } from "../components/TopologyGraph";
import type { Asset } from "../types";

const renderWithRouter = (ui: React.ReactElement) => {
  return render(<BrowserRouter>{ui}</BrowserRouter>);
};

describe("TopologyGraph Component", () => {
  it("renders graph title and canonical enterprise entities", () => {
    renderWithRouter(<TopologyGraph />);

    expect(
      screen.getByText(/Security Knowledge Graph & Attack Path Engine/i)
    ).toBeInTheDocument();
    expect(screen.getByText("Dijkstra & BFS Multigraph")).toBeInTheDocument();

    // Verify canonical node labels in canvas/details
    expect(screen.getAllByText("firewall-edge-01").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("server-prod-01").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("db-prod-01").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("ws-eng-100").length).toBeGreaterThanOrEqual(1);
  });

  it("displays Dijkstra Attack Path analysis by default", () => {
    renderWithRouter(<TopologyGraph />);

    expect(screen.getByText("Attack Path (Active)")).toBeInTheDocument();
    expect(
      screen.getByText(/Active Lateral Path to Crown Jewel Discovered/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/Dijkstra Critical Path Analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/RULE-GRAPH-BLAST-RADIUS/i)).toBeInTheDocument();
  });

  it("updates inspector card when selecting a different node", () => {
    renderWithRouter(<TopologyGraph />);

    // Click on db-prod-01 node
    const dbNode = screen.getByRole("button", { name: /Node Core Production Database/i });
    fireEvent.click(dbNode);

    // Inspector should now display Core Production Database details
    expect(screen.getByText("Core Production Database")).toBeInTheDocument();
    expect(screen.getByText("CROWN JEWEL")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.20")).toBeInTheDocument();
    expect(screen.getByText("View Alerts")).toBeInTheDocument();
    expect(screen.getByText("View Cases")).toBeInTheDocument();
  });

  it("simulates BFS blast radius from selected entity", () => {
    renderWithRouter(<TopologyGraph />);

    const blastButton = screen.getByText("Simulate Blast Radius");
    fireEvent.click(blastButton);

    // Blast radius simulation active
    expect(screen.getByText(/Blast Radius \(server-prod-01\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Transitive Blast Horizon/i)).toBeInTheDocument();
  });

  it("resets visual layers when Reset button is clicked", () => {
    renderWithRouter(<TopologyGraph />);

    // First toggle blast radius
    fireEvent.click(screen.getByText("Simulate Blast Radius"));
    expect(screen.getByText(/Blast Radius \(server-prod-01\)/i)).toBeInTheDocument();

    // Now click Reset
    const resetButton = screen.getByTitle("Reset highlight layers");
    fireEvent.click(resetButton);

    expect(screen.getByText("Trace Attack Path")).toBeInTheDocument();
    expect(screen.getByText("Simulate Blast Radius")).toBeInTheDocument();
    expect(screen.queryByText(/Dijkstra Critical Path Analysis/i)).not.toBeInTheDocument();
  });

  it("dynamically merges live CMDB assets including custom enrolled targets", () => {
    const liveAssets: Asset[] = [
      {
        id: "server-prod-01",
        hostname: "server-prod-01",
        ip_address: "192.168.1.10",
        asset_type: "server",
        criticality: "critical", // upgraded in CMDB
        description: "Enriched live server description",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: "cloud-s3-vault",
        hostname: "cloud-s3-vault",
        ip_address: "10.100.0.5",
        asset_type: "cloud_instance",
        criticality: "high",
        description: "Custom Enrolled AWS S3 Bucket",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    renderWithRouter(<TopologyGraph cmdbAssets={liveAssets} />);

    // Should indicate CMDB assets linked
    expect(screen.getByText(/2 CMDB Assets Linked/i)).toBeInTheDocument();

    // Custom asset should be on canvas
    expect(screen.getByText("cloud-s3-vault")).toBeInTheDocument();

    // Select custom asset
    const customNode = screen.getByRole("button", { name: /Node cloud-s3-vault/i });
    fireEvent.click(customNode);

    expect(screen.getByText("Custom Enrolled AWS S3 Bucket")).toBeInTheDocument();
    expect(screen.getByText("10.100.0.5")).toBeInTheDocument();
  });
});
