import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ToastProvider, useToast } from "../context/ToastContext";

const TestComponent: React.FC = () => {
  const { showToast } = useToast();
  return (
    <div>
      <button onClick={() => showToast("Test alert message", "success")}>
        Trigger Success Toast
      </button>
      <button onClick={() => showToast("Test error message", "error")}>
        Trigger Error Toast
      </button>
    </div>
  );
};

describe("ToastContext & Notification System", () => {
  it("renders toast notifications and allows manual dismissal", async () => {
    render(
      <ToastProvider>
        <TestComponent />
      </ToastProvider>
    );

    // Initial state: no toasts
    expect(screen.queryByText("Test alert message")).not.toBeInTheDocument();

    // Trigger success toast
    fireEvent.click(screen.getByText("Trigger Success Toast"));
    expect(screen.getByText("Test alert message")).toBeInTheDocument();

    // Trigger error toast
    fireEvent.click(screen.getByText("Trigger Error Toast"));
    expect(screen.getByText("Test error message")).toBeInTheDocument();

    // Dismiss first toast
    const dismissButtons = screen.getAllByRole("button", { name: /dismiss/i });
    expect(dismissButtons.length).toBe(2);

    fireEvent.click(dismissButtons[0]);
    expect(screen.queryByText("Test alert message")).not.toBeInTheDocument();
    expect(screen.getByText("Test error message")).toBeInTheDocument();
  });
});
