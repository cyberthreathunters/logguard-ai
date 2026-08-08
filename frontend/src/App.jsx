import { useState } from "react";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import Dashboard from "./pages/Dashboard.jsx";

export default function App() {
  const [loggedIn, setLoggedIn] = useState(!!localStorage.getItem("lg_token"));
  const [showRegister, setShowRegister] = useState(false);

  if (loggedIn) {
    return <Dashboard onLogout={() => setLoggedIn(false)} />;
  }

  if (showRegister) {
    return (
      <Register
        onBackToLogin={() => setShowRegister(false)}
        onRegistered={() => setShowRegister(false)}
      />
    );
  }

  return (
    <Login
      onLoggedIn={() => setLoggedIn(true)}
      onGoToRegister={() => setShowRegister(true)}
    />
  );
}
