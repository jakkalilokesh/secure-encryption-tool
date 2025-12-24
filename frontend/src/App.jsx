import { useState, useEffect } from "react";
import { HashRouter as Router, Routes, Route } from "react-router-dom";
import LayoutShell from "./layout/LayoutShell";
import InitialLoader from "./components/InitialLoader";

import Dashboard from "./pages/Dashboard";
import EncryptPage from "./pages/EncryptPage";
import DecryptPage from "./pages/DecryptPage";
import KeysPage from "./pages/KeysPage";

import StegPage from "./pages/StegPage";
import VaultPage from "./pages/VaultPage";

export default function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate initialization / backend ping check
    const timer = setTimeout(() => {
      setLoading(false);
    }, 2500); // 2.5s loader duration
    return () => clearTimeout(timer);
  }, []);

  return (
    <>
      {loading ? (
        <InitialLoader />
      ) : (
        <Router>
          <LayoutShell>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/encrypt" element={<EncryptPage />} />
              <Route path="/decrypt" element={<DecryptPage />} />
              <Route path="/keys" element={<KeysPage />} />
              <Route path="/steg" element={<StegPage />} />
              <Route path="/vault" element={<VaultPage />} />
            </Routes>
          </LayoutShell>
        </Router>
      )}
    </>
  );
}