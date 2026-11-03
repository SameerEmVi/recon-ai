import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid,
} from "recharts";
import { Server, Globe, Network, ShieldAlert, Activity } from "lucide-react";
import { getOverview } from "@/lib/api";
import { StatTile } from "@/components/StatTile";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

// Severity → color (matches the SOC palette).
const SEV_COLOR: Record<string, string> = {
  critical: "hsl(0 72% 55%)",
  high: "hsl(18 85% 55%)",
  medium: "hsl(38 92% 55%)",
  low: "hsl(142 50% 45%)",
  info: "hsl(215 30% 55%)",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function sevVariant(s: string): "critical" | "warning" | "success" | "default" {
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "warning";
  if (s === "low") return "success";
  return "default";
}

export default function Overview() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["overview"],
    queryFn: () => getOverview(),
    refetchInterval: 8_000,
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading overview…</p>;
  if (isError || !data)
    return <p className="text-sm text-critical">Could not load overview (is the backend reachable?).</p>;

  const sevData = SEV_ORDER.filter((s) => data.severity[s]).map((s) => ({
    name: s,
    value: data.severity[s],
  }));
  const techData = data.technologies.slice(0, 10);

  return (
    <div className="space-y-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold tracking-tight">Overview</h1>
        {data.scan && (
          <span className="text-xs text-muted-foreground">
            latest: <span className="text-foreground">{data.scan.domain}</span> · {data.scan.status}
          </span>
        )}
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Active scans" value={data.scans.running} icon={<Activity className="h-4 w-4" />}
          accent={data.scans.running ? "success" : undefined} />
        <StatTile label="Completed" value={data.scans.complete} />
        <StatTile label="Subdomains" value={data.assets.subdomains} icon={<Globe className="h-4 w-4" />} />
        <StatTile label="HTTP services" value={data.assets.http_services} icon={<Server className="h-4 w-4" />} />
        <StatTile label="Open ports" value={data.assets.open_ports} icon={<Network className="h-4 w-4" />} />
        <StatTile label="Findings" value={data.assets.findings} icon={<ShieldAlert className="h-4 w-4" />}
          accent={data.assets.findings ? "warning" : undefined} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Severity distribution */}
        <Card>
          <CardHeader><CardTitle>Vulnerability severity</CardTitle></CardHeader>
          <CardContent>
            {sevData.length === 0 ? (
              <p className="text-sm text-muted-foreground">No findings yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={sevData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(222 14% 18%)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: "hsl(215 14% 58%)", fontSize: 12 }} />
                  <YAxis allowDecimals={false} tick={{ fill: "hsl(215 14% 58%)", fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: "hsl(222 19% 11%)", border: "1px solid hsl(222 14% 18%)", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {sevData.map((d) => (
                      <Cell key={d.name} fill={SEV_COLOR[d.name] ?? SEV_COLOR.info} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Technology distribution */}
        <Card>
          <CardHeader><CardTitle>Technology distribution</CardTitle></CardHeader>
          <CardContent>
            {techData.length === 0 ? (
              <p className="text-sm text-muted-foreground">No technologies detected yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={techData} layout="vertical" margin={{ left: 24 }}>
                  <XAxis type="number" allowDecimals={false} tick={{ fill: "hsl(215 14% 58%)", fontSize: 12 }} />
                  <YAxis type="category" dataKey="name" width={120}
                    tick={{ fill: "hsl(215 14% 58%)", fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: "hsl(222 19% 11%)", border: "1px solid hsl(222 14% 18%)", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="count" fill="hsl(142 64% 42%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Recent events */}
        <Card>
          <CardHeader><CardTitle>Recent events</CardTitle></CardHeader>
          <CardContent className="max-h-72 space-y-1.5 overflow-auto">
            {data.recent_events.length === 0 ? (
              <p className="text-sm text-muted-foreground">No events yet.</p>
            ) : (
              data.recent_events.map((e, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <Badge variant="outline" className="shrink-0 font-mono">{e.type}</Badge>
                  <span className="truncate text-muted-foreground">{e.label}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-muted-foreground/70">{e.source}</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* Recent scans + worker/job utilisation */}
        <Card>
          <CardHeader><CardTitle>Recent scans</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {data.recent_scans.length === 0 ? (
              <p className="text-sm text-muted-foreground">No scans this session.</p>
            ) : (
              data.recent_scans.map((s) => (
                <div key={s.scan_id} className="flex items-center gap-2 text-xs">
                  <Badge variant={s.status === "running" ? "success" : s.status === "failed" ? "critical" : "default"}>
                    {s.status}
                  </Badge>
                  <span className="truncate text-foreground">{s.domain}</span>
                  <span className="ml-auto shrink-0 text-muted-foreground">{s.mode}</span>
                </div>
              ))
            )}
            {Object.keys(data.jobs).length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5 border-t border-border pt-2">
                {Object.entries(data.jobs).map(([state, n]) => (
                  <Badge key={state} variant="outline">{state}: {n}</Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {sevData.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {sevData.map((d) => (
            <Badge key={d.name} variant={sevVariant(d.name)}>
              {d.name}: {d.value}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
