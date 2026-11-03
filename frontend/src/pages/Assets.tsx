import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Server, Globe, Network, Boxes, Radio, Wifi } from "lucide-react";
import { getAssets, listScans, type AssetHost } from "@/lib/api";
import { StatTile } from "@/components/StatTile";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input, Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

type Tab = "hosts" | "subdomains" | "dns";

const TABS: { key: Tab; label: string }[] = [
  { key: "hosts", label: "Hosts" },
  { key: "subdomains", label: "Subdomains" },
  { key: "dns", label: "DNS records" },
];

function statusVariant(code: number | null): "success" | "warning" | "critical" | "default" {
  if (code == null) return "default";
  if (code >= 500) return "critical";
  if (code >= 400) return "warning";
  if (code >= 200 && code < 400) return "success";
  return "default";
}

export default function Assets() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 8_000 });
  const [scanId, setScanId] = useState<string>("");
  const [tab, setTab] = useState<Tab>("hosts");
  const [q, setQ] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);

  // Default to a running scan, else the most recent.
  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data, isLoading } = useQuery({
    queryKey: ["assets", scanId],
    queryFn: () => getAssets(scanId || undefined),
    refetchInterval: 8_000,
    enabled: true,
  });

  const needle = q.trim().toLowerCase();
  const hosts = useMemo(() => {
    let rows: AssetHost[] = data?.hosts ?? [];
    if (liveOnly) rows = rows.filter((h) => h.live);
    if (needle)
      rows = rows.filter(
        (h) =>
          h.hostname.toLowerCase().includes(needle) ||
          h.ips.some((ip) => ip.includes(needle)) ||
          h.technologies.some((t) => t.toLowerCase().includes(needle)) ||
          h.ports.some((p) => String(p).includes(needle))
      );
    return rows;
  }, [data, needle, liveOnly]);

  const subdomains = useMemo(
    () => (data?.subdomains ?? []).filter((s) => !needle || s.toLowerCase().includes(needle)),
    [data, needle]
  );
  const dns = useMemo(
    () =>
      (data?.dns_records ?? []).filter(
        (r) =>
          !needle ||
          r.hostname.toLowerCase().includes(needle) ||
          r.value.toLowerCase().includes(needle) ||
          r.record_type.toLowerCase().includes(needle)
      ),
    [data, needle]
  );

  const sum = data?.summary;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Asset Explorer</h1>
        <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-64">
          <option value="">Select a scan…</option>
          {(scans ?? []).map((s) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.domain} · {s.status}
            </option>
          ))}
        </Select>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Hosts" value={sum?.hosts ?? "—"} icon={<Server className="h-4 w-4" />} />
        <StatTile label="Live hosts" value={sum?.live_hosts ?? "—"} icon={<Wifi className="h-4 w-4" />}
          accent={sum?.live_hosts ? "success" : undefined} />
        <StatTile label="Subdomains" value={sum?.subdomains ?? "—"} icon={<Globe className="h-4 w-4" />} />
        <StatTile label="IPs" value={sum?.ips ?? "—"} icon={<Network className="h-4 w-4" />} />
        <StatTile label="Open ports" value={sum?.open_ports ?? "—"} icon={<Radio className="h-4 w-4" />} />
        <StatTile label="Technologies" value={sum?.technologies ?? "—"} icon={<Boxes className="h-4 w-4" />} />
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1 rounded-md border border-border bg-card p-1">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={cn(
                "rounded px-3 py-1 text-xs font-medium transition-colors",
                tab === t.key ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t.label}
              <span className="ml-1.5 text-[10px] text-muted-foreground/70">
                {t.key === "hosts" ? data?.hosts.length ?? 0
                  : t.key === "subdomains" ? data?.subdomains.length ?? 0
                  : data?.dns_records.length ?? 0}
              </span>
            </button>
          ))}
        </div>
        <Input
          placeholder="Filter…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="w-56"
        />
        {tab === "hosts" && (
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
            <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} />
            live only
          </label>
        )}
      </div>

      {!scanId ? (
        <p className="text-sm text-muted-foreground">Select a scan to explore its assets.</p>
      ) : isLoading ? (
        <p className="text-sm text-muted-foreground">Loading assets…</p>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>
              {tab === "hosts" ? `Hosts (${hosts.length})`
                : tab === "subdomains" ? `Subdomains (${subdomains.length})`
                : `DNS records (${dns.length})`}
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-[32rem] overflow-auto">
            {tab === "hosts" && (
              hosts.length === 0 ? (
                <p className="text-sm text-muted-foreground">No matching hosts.</p>
              ) : (
                <div className="space-y-2">
                  {hosts.map((h) => (
                    <div key={h.hostname} className="rounded-md border border-border/60 p-2.5">
                      <div className="flex items-center gap-2">
                        <span className={cn("h-2 w-2 shrink-0 rounded-full", h.live ? "bg-success" : "bg-muted-foreground/40")} />
                        <span className="truncate font-mono text-sm text-foreground">{h.hostname}</span>
                        <div className="ml-auto flex shrink-0 flex-wrap gap-1">
                          {h.ports.map((p) => <Badge key={p} variant="outline" className="font-mono">{p}</Badge>)}
                        </div>
                      </div>
                      {(h.ips.length > 0 || h.technologies.length > 0) && (
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 pl-4 text-xs">
                          {h.ips.map((ip) => (
                            <span key={ip} className="font-mono text-muted-foreground">{ip}</span>
                          ))}
                          {h.technologies.map((t) => (
                            <Badge key={t} variant="default">{t}</Badge>
                          ))}
                        </div>
                      )}
                      {h.services.length > 0 && (
                        <div className="mt-1.5 space-y-1 pl-4">
                          {h.services.map((sv, i) => (
                            <div key={`${sv.url}-${i}`} className="flex items-center gap-2 text-xs">
                              <Badge variant={statusVariant(sv.status_code)} className="shrink-0 font-mono">
                                {sv.status_code ?? "—"}
                              </Badge>
                              <span className="truncate text-muted-foreground">{sv.url}</span>
                              {sv.title && (
                                <span className="ml-auto shrink-0 truncate text-[10px] text-muted-foreground/70">
                                  {sv.title}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )
            )}

            {tab === "subdomains" && (
              subdomains.length === 0 ? (
                <p className="text-sm text-muted-foreground">No matching subdomains.</p>
              ) : (
                <div className="grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
                  {subdomains.map((s) => (
                    <span key={s} className="truncate font-mono text-xs text-muted-foreground">{s}</span>
                  ))}
                </div>
              )
            )}

            {tab === "dns" && (
              dns.length === 0 ? (
                <p className="text-sm text-muted-foreground">No matching DNS records.</p>
              ) : (
                <div className="space-y-1">
                  {dns.map((r, i) => (
                    <div key={`${r.hostname}-${r.record_type}-${i}`} className="flex items-center gap-2 text-xs">
                      <Badge variant="outline" className="w-14 shrink-0 justify-center font-mono">{r.record_type}</Badge>
                      <span className="shrink-0 truncate font-mono text-foreground">{r.hostname}</span>
                      <span className="ml-auto truncate font-mono text-muted-foreground">{r.value}</span>
                    </div>
                  ))}
                </div>
              )
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
