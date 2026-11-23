import type { ReactNode } from "react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import { useCountUp } from "@/lib/useCountUp";

/** A compact KPI tile for the dashboard.
 *  When `value` is a number it animates (counts up) as live data changes. */
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
    <Card className="hover-lift p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
        {icon && (
          <span
            className={cn(
              "text-muted-foreground transition-colors",
              accent === "success" && "text-success",
              accent === "warning" && "text-warning",
              accent === "critical" && "text-critical"
            )}
          >
            {icon}
          </span>
        )}
      </div>
      <div
        className={cn(
          "mt-2 text-2xl font-semibold tabular-nums",
          accent === "success" && "text-success",
          accent === "warning" && "text-warning",
          accent === "critical" && "text-critical"
        )}
      >
        {typeof value === "number" ? <AnimatedNumber value={value} /> : value}
      </div>
    </Card>
  );
}

function AnimatedNumber({ value }: { value: number }) {
  const n = useCountUp(value);
  return <>{n.toLocaleString()}</>;
}
