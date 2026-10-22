import React, { createContext, useContext, useState, useCallback } from "react";
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from "lucide-react";

export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  message: string;
  type: ToastType;
}

interface ToastContextType {
  showToast: (message: string, type?: ToastType, duration?: number) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    (message: string, type: ToastType = "info", duration: number = 4000) => {
      const id = Math.random().toString(36).substring(2, 9);
      setToasts((prev) => [...prev, { id, message, type }]);

      if (duration > 0) {
        setTimeout(() => {
          removeToast(id);
        }, duration);
      }
    },
    [removeToast]
  );

  const getToastIcon = (type: ToastType) => {
    switch (type) {
      case "success":
        return <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />;
      case "error":
        return <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />;
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />;
      case "info":
      default:
        return <Info className="h-4 w-4 text-cyan-400 shrink-0" />;
    }
  };

  const getToastStyles = (type: ToastType) => {
    switch (type) {
      case "success":
        return "border-emerald-500/40 bg-emerald-950/90 text-emerald-200 shadow-emerald-950/50";
      case "error":
        return "border-rose-500/40 bg-rose-950/90 text-rose-200 shadow-rose-950/50";
      case "warning":
        return "border-amber-500/40 bg-amber-950/90 text-amber-200 shadow-amber-950/50";
      case "info":
      default:
        return "border-cyan-500/40 bg-slate-900/95 text-cyan-200 shadow-cyan-950/50";
    }
  };

  return (
    <ToastContext.Provider value={{ showToast, removeToast }}>
      {children}
      {/* Toast Notification Container */}
      <div
        aria-live="assertive"
        className="pointer-events-none fixed inset-0 z-50 flex flex-col items-end px-4 py-6 sm:p-6 space-y-3"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role="alert"
            className={`pointer-events-auto flex items-center justify-between w-full max-w-sm rounded-lg border px-4 py-3 shadow-xl backdrop-blur-md transition-all duration-300 animate-in fade-in slide-in-from-top-4 ${getToastStyles(
              toast.type
            )}`}
          >
            <div className="flex items-center space-x-3">
              {getToastIcon(toast.type)}
              <p className="text-xs font-mono font-medium leading-relaxed">{toast.message}</p>
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="ml-3 inline-flex text-slate-400 hover:text-white transition-colors focus:outline-none"
              aria-label="Dismiss notification"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextType => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return context;
};
