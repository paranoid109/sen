import React from "react";
import { BrowserRouter, Routes, Route, Navigate, Outlet } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import { Navbar } from "./components/Navbar";
import { Sidebar } from "./components/Sidebar";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Alerts } from "./pages/Alerts";
import { Incidents } from "./pages/Incidents";
import { Assets } from "./pages/Assets";
import { Reports } from "./pages/Reports";
import { AdminAudit } from "./pages/AdminAudit";
import { CloudSecurity } from "./pages/CloudSecurity";

// Protected Layout wrapper
const ProtectedLayout: React.FC = () => {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-cyber-bg font-mono text-sm text-cyber-primary">
        Initialising SentinelX SOC Console...
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex h-screen flex-col bg-cyber-bg overflow-hidden">
      <Navbar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-7xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

// Role Guard wrapper
const RoleRoute: React.FC<{
  allowedRoles: Array<"Admin" | "Analyst" | "Auditor">;
  element: React.ReactElement;
}> = ({ allowedRoles, element }) => {
  const { hasRole } = useAuth();
  if (!hasRole(allowedRoles)) {
    return <Navigate to="/" replace />;
  }
  return element;
};

// Login Route: redirect if already authenticated
const PublicLoginRoute: React.FC = () => {
  const { user, isLoading } = useAuth();
  if (isLoading) {
    return null;
  }
  if (user) {
    return <Navigate to="/" replace />;
  }
  return <Login />;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<PublicLoginRoute />} />

            <Route element={<ProtectedLayout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/cloud" element={<CloudSecurity />} />
              <Route path="/reports" element={<Reports />} />
              <Route
                path="/admin"
                element={
                  <RoleRoute
                    allowedRoles={["Admin", "Auditor"]}
                    element={<AdminAudit />}
                  />
                }
              />
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
};

export default App;
