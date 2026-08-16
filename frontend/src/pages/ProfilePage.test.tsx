import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { ProfilePage } from "./ProfilePage";

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
    expect(
      screen.getByText("Operator identity (read-only)"),
    ).toBeInTheDocument();
  });

  it("shows the static operator identity", () => {
    renderPage();
    expect(
      screen.getByRole("heading", { name: "Operator", level: 2 }),
    ).toBeInTheDocument();
    expect(screen.getByText("OP")).toBeInTheDocument();
  });

  it("is explicit that no authentication exists", () => {
    renderPage();
    expect(
      screen.getByText(/No authentication or user management is implemented/),
    ).toBeInTheDocument();
  });

  it("offers no editable identity fields", () => {
    renderPage();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});