import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import App from "../App";
import { ThemeProvider } from "../theme/ThemeContext";

const mockLogin = vi.fn();
const mockLogout = vi.fn();
let mockAuthState: {
  user: null | { role: string; username: string; display_name: string };
  loading: boolean;
  isAuthenticated: boolean;
};

vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({
    ...mockAuthState,
    login: mockLogin,
    logout: mockLogout,
  }),
}));

function renderApp(entry = "/") {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[entry]}>
        <App />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

function resetAuth(overrides?: Partial<typeof mockAuthState>) {
  mockAuthState = {
    user: null,
    loading: false,
    isAuthenticated: false,
    ...overrides,
  };
  mockLogin.mockReset();
  mockLogout.mockReset();
}

describe("login flow", () => {
  it("renders LoginPage when unauthenticated", () => {
    resetAuth();
    renderApp();
    expect(screen.getByText("SAST Platform")).toBeInTheDocument();
    expect(screen.getByText("Demo Authentication")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /login/i })).toBeInTheDocument();
  });

  it("shows the demo accounts table", () => {
    resetAuth();
    renderApp();
    expect(
      screen.getByRole("heading", { name: "Demo Accounts" }),
    ).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
    expect(screen.getByText("manager")).toBeInTheDocument();
    expect(screen.getByText("developer")).toBeInTheDocument();
    expect(screen.getByText("auditor")).toBeInTheDocument();
  });

  it("does not show NotFoundPage when unauthenticated on any route", () => {
    resetAuth();
    renderApp("/some-random-route");
    expect(screen.getByText("SAST Platform")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Page not found" }),
    ).not.toBeInTheDocument();
  });

  it("calls auth.login when the form is submitted", async () => {
    resetAuth();
    mockLogin.mockResolvedValueOnce(undefined);
    const user = userEvent.setup();
    renderApp();

    await user.type(screen.getByLabelText(/^username$/i), "analyst");
    await user.type(screen.getByLabelText(/^password$/i), "demo123");
    await user.click(screen.getByRole("button", { name: /login/i }));

    expect(mockLogin).toHaveBeenCalledWith("analyst", "demo123");
  });

  it("shows an error message when login fails", async () => {
    resetAuth();
    mockLogin.mockRejectedValueOnce(
      new Error("Invalid username or password"),
    );
    const user = userEvent.setup();
    renderApp();

    await user.type(screen.getByLabelText(/^username$/i), "analyst");
    await user.type(screen.getByLabelText(/^password$/i), "wrong");
    await user.click(screen.getByRole("button", { name: /login/i }));

    expect(
      await screen.findByText("Invalid username or password"),
    ).toBeInTheDocument();
  });

  it("invalid credentials do NOT show 'Not Found'", async () => {
    resetAuth();
    mockLogin.mockRejectedValueOnce(
      new Error("Invalid username or password"),
    );
    const user = userEvent.setup();
    renderApp();

    await user.type(screen.getByLabelText(/^username$/i), "analyst");
    await user.type(screen.getByLabelText(/^password$/i), "wrong");
    await user.click(screen.getByRole("button", { name: /login/i }));

    const errorEl = await screen.findByText("Invalid username or password");
    expect(errorEl.textContent).not.toContain("Not Found");
  });

  it("can submit login for analyst", async () => {
    resetAuth();
    mockLogin.mockResolvedValueOnce(undefined);
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText(/^username$/i), "analyst");
    await user.type(screen.getByLabelText(/^password$/i), "demo123");
    await user.click(screen.getByRole("button", { name: /login/i }));
    expect(mockLogin).toHaveBeenCalledWith("analyst", "demo123");
  });

  it("can submit login for manager", async () => {
    resetAuth();
    mockLogin.mockResolvedValueOnce(undefined);
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText(/^username$/i), "manager");
    await user.type(screen.getByLabelText(/^password$/i), "demo123");
    await user.click(screen.getByRole("button", { name: /login/i }));
    expect(mockLogin).toHaveBeenCalledWith("manager", "demo123");
  });

  it("can submit login for developer", async () => {
    resetAuth();
    mockLogin.mockResolvedValueOnce(undefined);
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText(/^username$/i), "developer");
    await user.type(screen.getByLabelText(/^password$/i), "demo123");
    await user.click(screen.getByRole("button", { name: /login/i }));
    expect(mockLogin).toHaveBeenCalledWith("developer", "demo123");
  });

  it("can submit login for auditor", async () => {
    resetAuth();
    mockLogin.mockResolvedValueOnce(undefined);
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText(/^username$/i), "auditor");
    await user.type(screen.getByLabelText(/^password$/i), "demo123");
    await user.click(screen.getByRole("button", { name: /login/i }));
    expect(mockLogin).toHaveBeenCalledWith("auditor", "demo123");
  });

  it("does not read role from URL or localStorage", () => {
    resetAuth();
    window.localStorage.setItem("sast.role", "admin");
    renderApp("/?role=superadmin");
    expect(screen.getByText("SAST Platform")).toBeInTheDocument();
    expect(screen.queryByText("admin")).not.toBeInTheDocument();
    expect(screen.queryByText("superadmin")).not.toBeInTheDocument();
  });

  it("renders LoginPage when AuthContext returns null user (401 from /auth/me)", () => {
    resetAuth({ user: null, loading: false });
    renderApp();
    expect(screen.getByText("SAST Platform")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Page not found" }),
    ).not.toBeInTheDocument();
  });

  it("loading state does not flash NotFoundPage", () => {
    resetAuth({ user: null, loading: true });
    renderApp();
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Page not found" }),
    ).not.toBeInTheDocument();
  });

  it("unknown route renders NotFoundPage for authenticated users", () => {
    resetAuth({
      user: {
        role: "analyst",
        username: "analyst",
        display_name: "Analyst",
      },
      loading: false,
      isAuthenticated: true,
    });
    renderApp("/does-not-exist");
    expect(
      screen.getByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
  });

  it("unauthenticated user on root shows LoginPage, not NotFoundPage", () => {
    resetAuth();
    renderApp("/");
    expect(screen.getByText("SAST Platform")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Page not found" }),
    ).not.toBeInTheDocument();
  });
});
