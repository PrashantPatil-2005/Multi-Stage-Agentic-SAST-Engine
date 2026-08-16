import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { SettingsPage } from "./SettingsPage";

function renderPage() {
  return render(
    <MemoryRouter>
      <SettingsPage />
    </MemoryRouter>,
  );
}

describe("settings page", () => {
  it("renders the page with a read-only heading", () => {
    renderPage();
    expect(
      screen.getByRole("heading", { name: "Settings", level: 1 }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Platform configuration (read-only)"),
    ).toBeInTheDocument();
    expect(screen.getByText("Read-only")).toBeInTheDocument();
  });

  it("shows the platform configuration rows", () => {
    renderPage();
    expect(screen.getByText("Hugging Face (OpenAI-compatible)")).toBeInTheDocument();
    expect(screen.getByText("LLM_MODEL")).toBeInTheDocument();
    expect(screen.getByText("LLM_TIMEOUT_SECONDS")).toBeInTheDocument();
    expect(screen.getByText("SAST_DATABASE_URL")).toBeInTheDocument();
    expect(
      screen.getByText(/Built-in taint engine \(our-sast\)/),
    ).toBeInTheDocument();
  });

  it("lists the supported vulnerability rules", () => {
    renderPage();
    expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("Command Injection")).toBeInTheDocument();
    expect(screen.getByText("SSRF")).toBeInTheDocument();
  });

  it("shows the proof sandbox status", () => {
    renderPage();
    expect(
      screen.getByText(/Sandboxed execution; network access disabled/),
    ).toBeInTheDocument();
  });

  it("never displays secrets or an API key", () => {
    renderPage();
    expect(screen.queryByText(/api[_-]?key/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/hf_[A-Za-z0-9]+/)).not.toBeInTheDocument();
  });

  it("offers no edit or save controls", () => {
    renderPage();
    expect(
      screen.queryByRole("button", { name: /save|edit|apply/i }),
    ).not.toBeInTheDocument();
  });
});