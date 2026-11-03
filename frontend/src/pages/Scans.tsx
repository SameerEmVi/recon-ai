import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, X, Ban, ChevronDown, ChevronRight } from "lucide-react";
import {
  listScans, getCatalog, createScan, cancelScan, type ScanCreateBody, ApiError,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input, Textarea, Select, Field } from "@/components/ui/field";

const lines = (s: string): string[] | undefined => {
  const arr = s.split("\n").map((x) => x.trim()).filter(Boolean);
  return arr.length ? arr : undefined;
};
const numOrNull = (s: string): number | null => (s.trim() === "" ? null : Number(s));

function statusVariant(s: string): "success" | "warning" | "critical" | "default" {
  if (s === "running") return "success";
  if (s === "failed") return "critical";
  if (s === "cancelled") return "warning";
  return "default";
}

function NewScanForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const { data: catalog } = useQuery({ queryKey: ["catalog"], queryFn: getCatalog, staleTime: 60_000 });
  const [domain, setDomain] = useState("");
  const [mode, setMode] = useState("active");
  const [inScope, setInScope] = useState("");
  const [outScope, setOutScope] = useState("");
  const [maxDistance, setMaxDistance] = useState("5");
  const [rate, setRate] = useState("");
  const [conc, setConc] = useState("");
  const [modConc, setModConc] = useState("");
  const [hybrid, setHybrid] = useState(false);
  const [workers, setWorkers] = useState("10");
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState("chrome-windows");
  const [proxy, setProxy] = useState("");
  const [showModules, setShowModules] = useState(false);
  const [modules, setModules] = useState<Set<string>>(new Set());

  const mutation = useMutation({
    mutationFn: (body: ScanCreateBody) => createScan(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
      onClose();
    },
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const body: ScanCreateBody = {
      domain: domain.trim(),
      in_scope: lines(inScope),
      out_scope: lines(outScope) ?? [],
      max_distance: Number(maxDistance) || 5,
      mode,
      modules: modules.size ? Array.from(modules) : null,
      rate_limit: numOrNull(rate),
      max_concurrency: numOrNull(conc),
      module_concurrency: numOrNull(modConc),
      hybrid,
      workers: Number(workers) || 10,
      targets: hybrid ? lines(targets) ?? null : null,
      browser_profile: profile,
      proxy: proxy.trim() || null,
    };
    mutation.mutate(body);
  };

  const err = mutation.error instanceof ApiError ? mutation.error.message : null;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>New scan</CardTitle>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Target domain (seed)">
              <Input value={domain} onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com" required />
            </Field>
            <Field label="Mode">
              <Select value={mode} onChange={(e) => setMode(e.target.value)}>
                {(catalog?.modes ?? ["osint", "vuln", "active", "full"]).map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </Select>
            </Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="In-scope rules (one per line; blank = *.domain, domain)">
              <Textarea value={inScope} onChange={(e) => setInScope(e.target.value)}
                placeholder={"*.example.com\nexample.com"} />
            </Field>
            <Field label="Out-of-scope / exclusions (one per line)">
              <Textarea value={outScope} onChange={(e) => setOutScope(e.target.value)}
                placeholder={"admin.example.com"} />
            </Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-4">
            <Field label="Max distance"><Input type="number" min={0} max={10} value={maxDistance}
              onChange={(e) => setMaxDistance(e.target.value)} /></Field>
            <Field label="Rate /s (blank = unlimited)"><Input type="number" min={1} value={rate}
              onChange={(e) => setRate(e.target.value)} placeholder="unlimited" /></Field>
            <Field label="Max concurrency"><Input type="number" min={1} value={conc}
              onChange={(e) => setConc(e.target.value)} placeholder="unlimited" /></Field>
            <Field label="Per-host concurrency"><Input type="number" min={1} value={modConc}
              onChange={(e) => setModConc(e.target.value)} placeholder="unlimited" /></Field>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Browser profile"><Input value={profile}
              onChange={(e) => setProfile(e.target.value)} /></Field>
            <Field label="Proxy (optional, e.g. http://127.0.0.1:8080)"><Input value={proxy}
              onChange={(e) => setProxy(e.target.value)} placeholder="none" /></Field>
          </div>

          {/* Hybrid */}
          <div className="rounded-md border border-border p-3">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={hybrid} onChange={(e) => setHybrid(e.target.checked)} />
              Hybrid engine — scan multiple authorized subdomains concurrently
            </label>
            {hybrid && (
              <div className="mt-3 grid gap-4 sm:grid-cols-[120px_1fr]">
                <Field label="Workers"><Input type="number" min={1} max={50} value={workers}
                  onChange={(e) => setWorkers(e.target.value)} /></Field>
                <Field label="Targets (one host per line; blank = seed only)">
                  <Textarea value={targets} onChange={(e) => setTargets(e.target.value)}
                    placeholder={"www.example.com\napi.example.com"} />
                </Field>
              </div>
            )}
          </div>

          {/* Advanced: explicit module selection */}
          <div className="rounded-md border border-border">
            <button type="button" onClick={() => setShowModules((v) => !v)}
              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground">
              {showModules ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              Advanced: explicit modules ({modules.size || "mode defaults"})
            </button>
            {showModules && (
              <div className="max-h-48 overflow-auto border-t border-border p-3">
                <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                  {(catalog?.modules ?? []).map((m) => (
                    <label key={m.name} title={m.description}
                      className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <input type="checkbox" checked={modules.has(m.name)}
                        onChange={(e) => {
                          const next = new Set(modules);
                          e.target.checked ? next.add(m.name) : next.delete(m.name);
                          setModules(next);
                        }} />
                      <span className="truncate">{m.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

          {err && <p className="text-sm text-critical">{err}</p>}
          <div className="flex gap-2">
            <Button type="submit" disabled={!domain.trim() || mutation.isPending}>
              {mutation.isPending ? "Starting…" : "Start scan"}
            </Button>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function ScanTable() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000,
  });
  const cancel = useMutation({
    mutationFn: (id: string) => cancelScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading scans…</p>;
  const scans = data ?? [];
  if (scans.length === 0)
    return <p className="text-sm text-muted-foreground">No scans yet. Start one above.</p>;

  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead className="bg-panel text-left text-xs text-muted-foreground">
          <tr>
            <th className="px-3 py-2 font-medium">Domain</th>
            <th className="px-3 py-2 font-medium">Mode</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Events</th>
            <th className="px-3 py-2 font-medium">Started</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.scan_id} className="border-t border-border">
              <td className="px-3 py-2 font-medium text-foreground">{s.domain}</td>
              <td className="px-3 py-2 text-muted-foreground">{s.mode}</td>
              <td className="px-3 py-2"><Badge variant={statusVariant(s.status)}>{s.status}</Badge></td>
              <td className="px-3 py-2 tabular-nums text-muted-foreground">{s.event_count}</td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                {s.created_at ? new Date(s.created_at).toLocaleString() : "—"}
              </td>
              <td className="px-3 py-2 text-right">
                {s.status === "running" && (
                  <Button size="sm" variant="destructive" disabled={cancel.isPending}
                    onClick={() => cancel.mutate(s.scan_id)}>
                    <Ban className="h-3.5 w-3.5" /> Cancel
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Scans() {
  const [showForm, setShowForm] = useState(false);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold tracking-tight">Scan Management</h1>
        {!showForm && (
          <Button onClick={() => setShowForm(true)}>
            <Plus className="h-4 w-4" /> New scan
          </Button>
        )}
      </div>
      {showForm && <NewScanForm onClose={() => setShowForm(false)} />}
      <ScanTable />
    </div>
  );
}
