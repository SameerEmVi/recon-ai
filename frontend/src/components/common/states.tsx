import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

/** Empty state — icon, title, optional description + action. */
export function EmptyState({
  icon: Icon = Inbox, title, description, action, className,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex animate-fade-in flex-col items-center justify-center gap-2 px-6 py-16 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-border bg-card text-muted-foreground">
        <Icon className="h-5 w-5" />
      </div>
      <div className="text-sm font-medium text-foreground">{title}</div>
      {description && <div className="max-w-sm text-xs text-muted-foreground">{description}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

/** Spinner loading state for small regions (lists/panels use skeletons instead). */
export function LoadingState({ label = "Loading…", className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center justify-center gap-2 px-6 py-16 text-sm text-muted-foreground", className)}>
      <Loader2 className="h-4 w-4 animate-spin" />
      {label}
    </div>
  );
}

/** Error state with an optional retry. */
export function ErrorState({
  title = "Something went wrong", description, onRetry, className,
}: { title?: string; description?: string; onRetry?: () => void; className?: string }) {
  return (
    <div className={cn("flex animate-fade-in flex-col items-center justify-center gap-2 px-6 py-16 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-critical/40 bg-critical/10 text-critical">
        <AlertTriangle className="h-5 w-5" />
      </div>
      <div className="text-sm font-medium text-foreground">{title}</div>
      {description && <div className="max-w-sm text-xs text-muted-foreground">{description}</div>}
      {onRetry && (
        <button onClick={onRetry} className="mt-2 rounded-md border border-border px-3 py-1.5 text-xs text-foreground transition-colors hover:bg-accent">
          Retry
        </button>
      )}
    </div>
  );
}
