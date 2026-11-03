import type { ReactNode } from "react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";

/** A compact KPI tile for the dashboard. */
export function StatTile({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  accent?: "success" | "warning" | "critical";
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
        {icon && <span className="text-muted-foreground">{icon}</span>}
      </div>
      <div
        className={cn(
          "mt-2 text-2xl font-semibold tabular-nums",
          accent === "success" && "text-success",
          accent === "warning" && "text-warning",
          accent === "critical" && "text-critical"
        )}
      >
        {value}
      </div>
    </Card>
  );
}
