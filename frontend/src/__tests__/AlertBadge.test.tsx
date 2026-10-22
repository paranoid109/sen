import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  SeverityBadge,
  AlertStatusBadge,
  IncidentStatusBadge,
  RiskScoreBadge,
} from "../components/AlertBadge";

describe("AlertBadge Components", () => {
  it("renders SeverityBadge correctly for all levels", () => {
    const { rerender } = render(<SeverityBadge severity="critical" />);
    expect(screen.getByText(/critical/i)).toBeInTheDocument();

    rerender(<SeverityBadge severity="high" />);
    expect(screen.getByText(/high/i)).toBeInTheDocument();

    rerender(<SeverityBadge severity="medium" />);
    expect(screen.getByText(/medium/i)).toBeInTheDocument();

    rerender(<SeverityBadge severity="low" />);
    expect(screen.getByText(/low/i)).toBeInTheDocument();
  });

  it("renders AlertStatusBadge correctly for states", () => {
    const { rerender } = render(<AlertStatusBadge status="NEW" />);
    expect(screen.getByText("NEW")).toBeInTheDocument();

    rerender(<AlertStatusBadge status="INVESTIGATING" />);
    expect(screen.getByText("INVESTIGATING")).toBeInTheDocument();

    rerender(<AlertStatusBadge status="RESOLVED" />);
    expect(screen.getByText("RESOLVED")).toBeInTheDocument();

    rerender(<AlertStatusBadge status="FALSE_POSITIVE" />);
    expect(screen.getByText("FALSE_POSITIVE")).toBeInTheDocument();
  });

  it("renders IncidentStatusBadge correctly for states", () => {
    const { rerender } = render(<IncidentStatusBadge status="OPEN" />);
    expect(screen.getByText("OPEN")).toBeInTheDocument();

    rerender(<IncidentStatusBadge status="CLOSED" />);
    expect(screen.getByText("CLOSED")).toBeInTheDocument();
  });

  it("renders RiskScoreBadge with correct numeric value and bounds", () => {
    const { rerender } = render(<RiskScoreBadge score={85} />);
    expect(screen.getByText(/RISK 85\/100/i)).toBeInTheDocument();

    rerender(<RiskScoreBadge score={0} />);
    expect(screen.getByText(/RISK 0\/100/i)).toBeInTheDocument();

    rerender(<RiskScoreBadge score={100} />);
    expect(screen.getByText(/RISK 100\/100/i)).toBeInTheDocument();
  });
});
