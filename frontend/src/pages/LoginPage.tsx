import { FormEvent, useState } from "react";
import { useAuth } from "../context/AuthContext";
import "./login.css";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(username, password);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <h1>SAST Platform</h1>
          <span className="login-badge">Demo Authentication</span>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {error && <div className="login-error">{error}</div>}

          <label className="login-label">
            Username
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="login-input"
              autoComplete="username"
              autoFocus
            />
          </label>

          <label className="login-label">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="login-input"
              autoComplete="current-password"
            />
          </label>

          <button
            type="submit"
            className="login-button"
            disabled={submitting}
          >
            {submitting ? "Logging in…" : "Login"}
          </button>
        </form>

        <div className="login-demo-accounts">
          <h3>Demo Accounts</h3>
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>analyst</td>
                <td>demo123</td>
                <td>Security Analyst</td>
              </tr>
              <tr>
                <td>manager</td>
                <td>demo123</td>
                <td>Security Manager</td>
              </tr>
              <tr>
                <td>developer</td>
                <td>demo123</td>
                <td>Developer</td>
              </tr>
              <tr>
                <td>auditor</td>
                <td>demo123</td>
                <td>Auditor</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
