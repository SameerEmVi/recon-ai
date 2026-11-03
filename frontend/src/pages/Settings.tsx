import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { getConfig } from "@/lib/api";
import { getToken, setToken, clearToken } from "@/lib/auth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/field";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  );
}

export default function Settings() {
  const { data: cfg, isLoading, isError } = useQuery({ queryKey: ["config"], queryFn: getConfig });
  const [draft, setDraft] = useState("");
  const hasToken = !!getToken();

  const saveToken = () => {
    if (!draft.trim()) return;
    setToken(draft);
    window.location.reload();   // re-run all queries with the new token
  };
  const signOut = () => {
    clearToken();
    window.location.reload();   // TokenGate re-prompts
  };

  const loopback = cfg?.server.loopback ?? true;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold tracking-tight">Settings</h1>

      {/* Security posture */}
      <Card>
        <CardHeader><CardTitle>Security posture</CardTitle></CardHeader>
        <CardContent className="space-y-1">
          <div className="mb-2 flex items-center gap-2 text-sm">
            {loopback ? (
              <><ShieldCheck className="h-4 w-4 text-success" />
                <span className="text-success">Bound to loopback — local-only.</span></>
            ) : (
              <><ShieldAlert className="h-4 w-4 text-warning" />
                <span className="text-warning">
                  Bound to a non-loopback address — the token is the only gate. Keep it secret.
                </span></>
            )}
          </div>
          <Row label="Bind address">
            <span className="font-mono">{cfg ? `${cfg.server.host}:${cfg.server.port}` : "—"}</span>
          </Row>
          <Row label="Access token">
            {cfg?.auth.token_set ? (
              <Badge variant={cfg.auth.token_source === "env" ? "success" : "warning"}>
                {cfg.auth.token_source === "env" ? "set via env (persistent)" : "generated at startup"}
              </Badge>
            ) : <Badge variant="critical">not set</Badge>}
          </Row>
          <Row label="CORS allow-list">
            <span className="font-mono text-xs">{cfg?.cors_origins.join(", ") || "—"}</span>
          </Row>
        </CardContent>
      </Card>

      {/* Backend configuration (read-only) */}
      <Card>
        <CardHeader><CardTitle>Backend configuration</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : isError || !cfg ? (
            <p className="text-sm text-critical">Could not load configuration.</p>
          ) : (
            <div className="divide-y divide-border/50">
              <Row label="Version"><span className="font-mono">{cfg.version}</span></Row>
              <Row label="Database">
                {cfg.database.configured
                  ? <Badge variant="success">{cfg.database.dialect ?? "configured"}</Badge>
                  : <Badge>not configured (read-only features limited)</Badge>}
              </Row>
              <Row label="Proxy (env)">
                {cfg.proxy.env_configured ? <Badge variant="success">configured</Badge> : <Badge>off</Badge>}
              </Row>
              <Row label="Results directory"><span className="font-mono text-xs">{cfg.results_dir}</span></Row>
              <Row label="Modes">
                <span className="flex flex-wrap justify-end gap-1">
                  {cfg.modes.map((m) => <Badge key={m} variant="outline">{m}</Badge>)}
                </span>
              </Row>
              <Row label="Worker default / ceiling">
                <span className="font-mono">{cfg.defaults.workers} / {cfg.defaults.worker_ceiling}</span>
              </Row>
              <Row label="Max scope distance"><span className="font-mono">{cfg.defaults.max_distance}</span></Row>
              <Row label="Browser profiles">
                <span className="font-mono text-xs">{cfg.browser_profiles.join(", ")}</span>
              </Row>
            </div>
          )}
          <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
            These values are set at server startup via environment variables
            (<code>RECON_AI_WEB_*</code>, <code>RECON_AI_DB_URL</code>,{" "}
            <code>RECON_AI_RESULTS_DIR</code>, <code>RECON_AI_PROXY</code>). The GUI never
            exposes the token or the database URL.
          </p>
        </CardContent>
      </Card>

      {/* Token management (client-side) */}
      <Card>
        <CardHeader><CardTitle>Access token (this browser)</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            The token is stored only in this browser's localStorage. Replace it if the
            server was restarted with a new one, or sign out to clear it.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Input type="password" value={draft} onChange={(e) => setDraft(e.target.value)}
              placeholder={hasToken ? "Paste a new token…" : "Paste the token…"} className="w-72" />
            <Button variant="outline" onClick={saveToken} disabled={!draft.trim()}>Replace token</Button>
            <Button variant="destructive" onClick={signOut} disabled={!hasToken}>Sign out</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
