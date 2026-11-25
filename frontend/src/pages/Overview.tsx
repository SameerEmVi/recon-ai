import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import {
  Activity, Globe, Server, Network, ShieldAlert, Link2, Bug, Siren, Plus, Cpu, ArrowRight,
} from "lucide-react";
import { getOverview, getFindings } from "@/lib/api";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { SeverityChart } from "@/components/dashboard/SeverityChart";
import { ActivityFeed } from "@/components/dashboard/ActivityFeed";
import { ScanSummary } from "@/components/dashboard/ScanSummary";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StatusIndicator, type StatusTone, severityTone } from "@/components/common/StatusIndicator";
import { EmptyState } from "@/components/common/states";
import { Skeleton, SkeletonTiles } from "@/components/ui/skeleton";

const STATUS_TONE: Record<string, StatusTone> = {
  running: "running", complete: "success", failed: "critical", cancelled: "warning",
};

function Panel({ title, action, children, className }: {
  title: string; action?: React.ReactNode; children: React.ReactNode; className?: string;
}) {
  return (
    <Card className={className}>
      <CardHeader className="flex-row items-center justify-between gap-2">
        <CardTitle>{title}</CardTitle>
        {action}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export default function Overview() {
  const navigate = useNavigate();
  const { data, isLoading, isError, dataUpdatedAt } = useQuery({
    queryKey: ["overview"], queryFn: () => getOverview(), refetchInterval: 8_000,
  });
  // Top findings by severity — "critical findings requiring attention".
  const { data: topFindings } = useQuery({
    queryKey: ["findings", { sort: "severity", page_size: 6, _overview: true }],
    queryFn: () => getFindings({ sort: "severity", page_size: 6 }),
    refetchInterval: 15_000,
  });

  if (isLoading)
    return (
      <div className="space-y-5">
        <Skeleton className="h-8 w-48" />
        <SkeletonTiles count={8} />
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-64 w-full" /><Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  if (isError || !data)
    return <EmptyState icon={ShieldAlert} title="Could not load the command centre"
      description="The backend is unreachable. Check the server and your token." />;

  const a = data.assets;
  const critical = data.severity.critical ?? 0;
  const attention = (topFindings?.findings ?? []).filter(
    (f) => ["critical", "high"].includes((f.severity || "").toLowerCase()));
  const updated = dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : "—";
  const tech = data.technologies.slice(0, 10);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">Command Centre</h1>
          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
            {data.scan ? (
              <>
                <StatusIndicator tone={STATUS_TONE[data.scan.status] ?? "muted"} pulse={data.scan.status === "running"} />
                <span>Latest: <span className="font-medium text-foreground">{data.scan.domain}</span></span>
                <span className="text-border">·</span>
                <span className="capitalize">{data.scan.status}</span>
                <span className="text-border">·</span>
              </>
            ) : null}
            <span>updated <span className="tabular-nums">{updated}</span></span>
          </div>
        </div>
        <Button onClick={() => navigate("/scans")}><Plus className="h-4 w-4" /> New scan</Button>
      </div>

      {/* KPI cards — every metric is real and drills into its page */}
      <div className="stagger grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8">
        <MetricCard label="Active scans" value={data.scans.running} icon={Activity}
          tone={data.scans.running ? "success" : "default"} to="/monitor" hint={`${data.scans.total} total`} />
        <MetricCard label="Subdomains" value={a.subdomains} icon={Globe} tone="primary" to="/assets" />
        <MetricCard label="Hosts" value={a.hosts} icon={Server} to="/assets" />
        <MetricCard label="HTTP services" value={a.http_services} icon={Cpu} to="/assets" />
        <MetricCard label="Open ports" value={a.open_ports} icon={Network} to="/assets" />
        <MetricCard label="URLs" value={a.urls} icon={Link2} to="/assets" />
        <MetricCard label="Findings" value={a.findings} icon={Bug} tone={a.findings ? "warning" : "default"} to="/findings" />
        <MetricCard label="Critical" value={critical} icon={Siren} tone={critical ? "critical" : "default"} to="/vulnerabilities" />
      </div>

      {/* Charts */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Vulnerability severity"
          action={<button onClick={() => navigate("/vulnerabilities")} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-primary">view <ArrowRight className="h-3 w-3" /></button>}>
          <SeverityChart severity={data.severity} />
        </Panel>

        <Panel title="Technology distribution"
          action={<button onClick={() => navigate("/assets")} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-primary">assets <ArrowRight className="h-3 w-3" /></button>}>
          {tech.length === 0 ? (
            <EmptyState icon={Cpu} title="No technologies detected yet" />
          ) : (
            <ResponsiveContainer width="100%" height={210}>
              <BarChart data={tech} layout="vertical" margin={{ left: 8, right: 12, top: 4, bottom: 0 }}>
                <XAxis type="number" allowDecimals={false} tick={{ fill: "hsl(215 20% 65%)", fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={120} tick={{ fill: "hsl(214 50% 85%)", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "hsl(218 42% 15% / 0.5)" }}
                  contentStyle={{ background: "hsl(218 42% 15%)", border: "1px solid hsl(218 35% 21%)", borderRadius: 10, fontSize: 12 }} />
                <Bar dataKey="count" radius={[0, 5, 5, 0]} cursor="pointer" onClick={() => navigate("/assets")}>
                  {tech.map((_, i) => <Cell key={i} fill={i % 2 ? "hsl(234 89% 74%)" : "hsl(199 93% 60%)"} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>

      {/* Critical findings requiring attention */}
      {attention.length > 0 && (
        <Panel title="Findings requiring attention"
          action={<button onClick={() => navigate("/findings")} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-primary">all findings <ArrowRight className="h-3 w-3" /></button>}>
          <div className="space-y-1">
            {attention.map((f) => (
              <button key={f.id} onClick={() => navigate("/findings")}
                className="flex w-full items-center gap-3 rounded-md px-1.5 py-1.5 text-left text-xs transition-colors hover:bg-accent/40">
                <Badge variant={severityTone(f.severity) === "critical" ? "critical" : "warning"} className="shrink-0 uppercase">{f.severity}</Badge>
                <span className="truncate font-medium text-foreground">{f.title}</span>
                <span className="ml-auto shrink-0 truncate font-mono text-[11px] text-muted-foreground">{f.host}</span>
              </button>
            ))}
          </div>
        </Panel>
      )}

      {/* Feeds */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Recent reconnaissance">
          <ActivityFeed events={data.recent_events} />
        </Panel>
        <Panel title="Recent scans">
          <ScanSummary scans={data.recent_scans} jobs={data.jobs} />
        </Panel>
      </div>
    </div>
  );
}
