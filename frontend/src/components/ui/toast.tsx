import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { CheckCircle2, AlertTriangle, Info, X, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";

type ToastKind = "success" | "error" | "warning" | "info";
type Toast = { id: number; kind: ToastKind; title: string; message?: string };

type ToastCtx = {
  push: (t: Omit<Toast, "id">) => void;
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  warning: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
};

const Ctx = createContext<ToastCtx | null>(null);

const ICON: Record<ToastKind, typeof CheckCircle2> = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};
const ACCENT: Record<ToastKind, string> = {
  success: "text-success",
  error: "text-critical",
  warning: "text-warning",
  info: "text-primary",
};

let _id = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = ++_id;
    setToasts((ts) => [...ts, { ...t, id }].slice(-4)); // cap visible toasts
    window.setTimeout(() => remove(id), 4200);
  }, [remove]);

  const api: ToastCtx = {
    push,
    success: (title, message) => push({ kind: "success", title, message }),
    error: (title, message) => push({ kind: "error", title, message }),
    warning: (title, message) => push({ kind: "warning", title, message }),
    info: (title, message) => push({ kind: "info", title, message }),
  };

  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2">
        {toasts.map((t) => (
          <ToastRow key={t.id} toast={t} onClose={() => remove(t.id)} />
        ))}
      </div>
    </Ctx.Provider>
  );
}

function ToastRow({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const Icon = ICON[toast.kind];
  const [leaving, setLeaving] = useState(false);
  // Auto-mount animation handled by CSS; this just powers a graceful exit.
  useEffect(() => {
    const t = window.setTimeout(() => setLeaving(true), 3900);
    return () => window.clearTimeout(t);
  }, []);
  return (
    <div
      role="status"
      className={cn(
        "pointer-events-auto flex items-start gap-3 rounded-lg border border-border bg-panel/95 p-3 shadow-xl backdrop-blur",
        leaving ? "animate-fade-in opacity-0 transition-opacity duration-300" : "animate-slide-in-right"
      )}
    >
      <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", ACCENT[toast.kind])} />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-foreground">{toast.title}</p>
        {toast.message && (
          <p className="mt-0.5 break-words text-xs text-muted-foreground">{toast.message}</p>
        )}
      </div>
      <button
        onClick={onClose}
        className="shrink-0 text-muted-foreground transition-colors hover:text-foreground"
        aria-label="Dismiss"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export function useToast(): ToastCtx {
  const ctx = useContext(Ctx);
  if (!ctx) {
    // Fail-safe no-op so a component outside the provider never crashes.
    const noop = () => {};
    return { push: noop, success: noop, error: noop, warning: noop, info: noop };
  }
  return ctx;
}
