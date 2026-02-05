import React, { createContext, useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../api/client";
import { toast } from "sonner";

interface User {
  _id: string;
  username: string;
  email: string;
  fullName?: string;
  avatar?: { url: string };
  role?: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (data: any) => Promise<void>;
  register: (data: any) => Promise<{ email: string; message?: string } | void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  const checkAuth = async () => {
    try {
      setIsLoading(true);
      const response = await apiClient.get("/auth/current-user");
      setUser(response.data.data);
    } catch (error) {
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      setIsLoading(false);
      const publicPaths = ["/login", "/register", "/forgot-password", "/reset-password", "/verify-email"];
      const isOnPublicPath = publicPaths.some((path) =>
        window.location.pathname.startsWith(path),
      );
      if (!isOnPublicPath) {
        navigate("/login");
      }
    };

    window.addEventListener("auth:unauthorized", handleUnauthorized as EventListener);
    return () => {
      window.removeEventListener("auth:unauthorized", handleUnauthorized as EventListener);
    };
  }, [navigate]);

  const login = async (data: any) => {
    const response = await apiClient.post("/auth/login", data);
    setUser(response.data.data.user);
  };

  const register = async (data: any) => {
    const response = await apiClient.post("/auth/register", data);
    // PRD: Do not auto-login - user must verify email first
    return { email: data.email, message: response.data.message } as {
      email: string;
      message?: string;
    };
  };

  const logout = async () => {
    try {
      await apiClient.post("/auth/logout");
      setUser(null);
      toast.success("Logged out");
    } catch (error) {
      console.error("Logout failed", error);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        checkAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
