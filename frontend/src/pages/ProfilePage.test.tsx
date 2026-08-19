import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { ProfilePage } from "./ProfilePage";

vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({
    user: { role: "analyst", username: "analyst", display_name: "Security Analyst" },
    loading: false,
    isAuthenticated: true,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <ProfilePage />
    </MemoryRouter>,
  );
}

describe("profile page", () => {
  it("renders the page with a heading", () => {
    renderPage();
    expect(
      screen.getByRole("heading", { name: "Profile", level: 1 }),
    ).toBeInTheDocument();
  });

  it("shows the authenticated user identity", () => {
    renderPage();
    expect(screen.getByText("Security Analyst")).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
  });

  it("offers no editable identity fields", () => {
    renderPage();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });
});
