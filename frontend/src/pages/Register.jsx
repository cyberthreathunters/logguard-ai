import { useState } from "react";
import { register } from "../api.js";

export default function Register({ onRegistered, onBackToLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords don't match");
      return;
    }
    if (password.length < 8) {
      setError("Password should be at least 8 characters");
      return;
    }

    setLoading(true);
    try {
      const data = await register(email, password);
      if (data.error) throw new Error(data.error);
      setSuccess(true);
    } catch (err) {
      setError(err.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <div className="login-logo">
            LogGuard <span className="dot">AI</span>
          </div>
          <p className="login-sub">Account created — you can sign in now.</p>
          <button onClick={onBackToLogin}>Go to sign in</button>
        </div>
      </div>
    );
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-logo">
          LogGuard <span className="dot">AI</span>
        </div>
        <p className="login-sub">Create an admin account</p>

        <label>Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />

        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        <label>Confirm password</label>
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />

        {error && <div className="login-error">{error}</div>}

        <button type="submit" disabled={loading}>
          {loading ? "Creating account..." : "Create account"}
        </button>

        <button type="button" className="link-btn" onClick={onBackToLogin}>
          Already have an account? Sign in
        </button>
      </form>
    </div>
  );
}
