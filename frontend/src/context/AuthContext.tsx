import React, { createContext, useContext, useEffect, useState } from "react";
import { authApi } from "../services/api";
import type { User, UserRole } from "../types";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (allowedRoles: UserRole[]) => boolean;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = sessionStorage.getItem("sentinelx_user");
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState<string | null>(() => {
    return sessionStorage.getItem("sentinelx_token");
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      const storedToken = sessionStorage.getItem("sentinelx_token");
      if (storedToken) {
        try {
          const currentUser = await authApi.getMe();
          setUser(currentUser);
          sessionStorage.setItem("sentinelx_user", JSON.stringify(currentUser));
        } catch {
          sessionStorage.removeItem("sentinelx_token");
          sessionStorage.removeItem("sentinelx_user");
          setUser(null);
          setToken(null);
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await authApi.login(username, password);
      sessionStorage.setItem("sentinelx_token", res.access_token);
      setToken(res.access_token);

      const currentUser = await authApi.getMe();
      setUser(currentUser);
      sessionStorage.setItem("sentinelx_user", JSON.stringify(currentUser));
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    sessionStorage.removeItem("sentinelx_token");
    sessionStorage.removeItem("sentinelx_user");
    setUser(null);
    setToken(null);
  };

  const hasRole = (allowedRoles: UserRole[]): boolean => {
    if (!user) return false;
    return allowedRoles.includes(user.role);
  };

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
