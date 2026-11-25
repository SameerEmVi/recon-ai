import { getToken } from "./auth";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Fetch a JSON API endpoint, injecting the bearer token. Throws ApiError on
 * non-2xx (401 => the token gate can react). */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, String(detail));
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// Typed helpers used across pages.
export interface Health {
  status: string;
  version: string;
  db_configured: boolean;
  active_scans: number;
}

export interface ScanStatus {
  scan_id: string;
  domain: string;
  status: "running" | "complete" | "failed" | "cancelled" | "not_found" | "unknown";
  mode?: string | null;
  event_count: number;
  error?: string | null;
  created_at?: string | null;
  completed_at?: string | null;
}

export interface Overview {
  scans: { running: number; complete: number; failed: number; cancelled: number; total: number };
  recent_scans: { scan_id: string; domain: string; status: string; mode: string; created_at: string | null }[];
  scan: {
    scan_id: string; domain: string; status: string; mode: string; event_count: number;
    created_at: string | null; completed_at: string | null;
  } | null;
  assets: {
    subdomains: number; hosts: number; http_services: number; urls: number;
    open_ports: number; findings: number;
  };
  severity: Record<string, number>;
  technologies: { name: string; count: number }[];
  recent_events: { type: string; label: string; source: string; at: string | null }[];
  jobs: Record<string, number>;
}

export interface HostService {
  url: string;
  status_code: number | null;
  title: string | null;
}
export interface AssetHost {
  hostname: string;
  live: boolean;
  ips: string[];
  ports: number[];
  technologies: string[];
  services: HostService[];
}
export interface DnsRecord {
  hostname: string;
  record_type: string;
  value: string;
}
export interface Assets {
  scan: { scan_id: string; domain: string; status: string; mode: string; created_at: string | null } | null;
  summary: {
    hosts: number; live_hosts: number; subdomains: number; ips: number;
    open_ports: number; services: number; dns_records: number; technologies: number;
  };
  hosts: AssetHost[];
  subdomains: string[];
  dns_records: DnsRecord[];
  technologies: { name: string; count: number }[];
}

export interface VulnFinding {
  id: string;
  host: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  status: string | null;
  confidence: number | null;
  confidence_label: string | null;
  detection_method: string | null;
  tier: string | null;
  references: string | null;
  remediation: string | null;
  url: string | null;
  extra: Record<string, unknown>;
  created_at: string | null;
}
export interface Vulns {
  scan: { scan_id: string; domain: string; status: string; mode: string; created_at: string | null } | null;
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_confidence: Record<string, number>;
  };
  findings: VulnFinding[];
}

export interface DiagRun {
  domain: string;
  run_id: string;
  modified: number;
  total_errors: number;
  errors_by_category: Record<string, number>;
  errors_by_module: Record<string, number>;
  streams: Record<string, number>;
}
export interface DiagRecord {
  timestamp?: string;
  level?: string;
  event?: string;
  module?: string | null;
  target?: string;
  method?: string;
  status?: number | null;
  duration_ms?: number | null;
  error_type?: string;
  [k: string]: unknown;
}
export interface Diagnostics {
  run: DiagRun | null;
  stream: string;
  records: DiagRecord[];
  available_runs: DiagRun[];
}
export interface ProxyCheck {
  ok: boolean;
  target: string;
  message: string;
}

export interface AppConfig {
  version: string;
  server: { host: string; port: number; loopback: boolean };
  auth: { token_set: boolean; token_source: "env" | "generated" };
  database: { configured: boolean; dialect: string | null };
  proxy: { env_configured: boolean };
  cors_origins: string[];
  results_dir: string;
  defaults: { max_distance: number; workers: number; worker_ceiling: number; browser_profile: string };
  modes: string[];
  browser_profiles: string[];
}

export type GraphKind =
  | "domain" | "host" | "ip" | "service" | "port"
  | "tech" | "url" | "finding" | "anomaly" | "email";
export interface GraphNode {
  id: string;
  kind: GraphKind;
  label: string;
  // optional, kind-specific
  status?: number;
  title?: string;
  server?: string;
  url?: string;
  port?: number;
  version?: string;
  category?: string;
  severity?: string;
  method?: string;
  description?: string;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  rel: string;
}
export interface Graph {
  scan: { scan_id: string; domain: string; status: string; mode: string } | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: { nodes: number; edges: number; by_kind: Record<string, number> };
  truncated: boolean;
}

export interface PlanModule {
  module: string;
  state: string;
  error: string | null;
}
export interface PlanTarget {
  target: string;
  state: string | null;
  modules: PlanModule[];
}
export interface Plan {
  scan: { scan_id: string; domain: string; status: string; mode: string } | null;
  is_hybrid: boolean;
  targets: PlanTarget[];
  summary: { targets: number; modules: number; by_state: Record<string, number> };
}

export interface Catalog {
  modules: { name: string; description: string; flags: string[] }[];
  modes: string[];
  profiles: { name: string; description: string }[];
}

export interface ScanCreateBody {
  domain: string;
  in_scope?: string[];
  out_scope?: string[];
  max_distance?: number;
  wildcard_apex?: boolean;
  mode?: string;
  modules?: string[] | null;
  rate_limit?: number | null;
  max_concurrency?: number | null;
  module_concurrency?: number | null;
  hybrid?: boolean;
  workers?: number;
  targets?: string[] | null;
  browser_profile?: string;
  proxy?: string | null;
}

export interface ScanCreated {
  scan_id: string;
  domain: string;
  status: string;
  mode: string;
}

export const getHealth = () => apiFetch<Health>("/api/health");
export const listScans = () => apiFetch<ScanStatus[]>("/api/scans");
export const getCatalog = () => apiFetch<Catalog>("/api/catalog");
export const createScan = (body: ScanCreateBody) =>
  apiFetch<ScanCreated>("/api/scans", { method: "POST", body: JSON.stringify(body) });
export const cancelScan = (id: string) =>
  apiFetch<ScanStatus>(`/api/scans/${id}/cancel`, { method: "POST" });
export const getOverview = (scanId?: string) =>
  apiFetch<Overview>("/api/overview" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""));
export const getAssets = (scanId?: string) =>
  apiFetch<Assets>("/api/assets" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""));
export const getVulns = (scanId?: string) =>
  apiFetch<Vulns>("/api/vulns" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""));
export const getGraph = (scanId?: string) =>
  apiFetch<Graph>("/api/graph" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""));
export const getPlan = (scanId?: string) =>
  apiFetch<Plan>("/api/plan" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""));
export const getDiagnostics = (params: { domain?: string; run_id?: string; stream?: string; module?: string } = {}) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
  const q = qs.toString();
  return apiFetch<Diagnostics>("/api/diagnostics" + (q ? `?${q}` : ""));
};
export const checkProxy = (url: string) =>
  apiFetch<ProxyCheck>("/api/diagnostics/proxy-check", { method: "POST", body: JSON.stringify({ url }) });
export const getConfig = () => apiFetch<AppConfig>("/api/config");

// ── Traffic (proxy-style HTTP exchange viewer, backed by http.jsonl) ──────────
export interface TrafficFlow {
  time: string | null;
  module: string | null;
  operation: string | null;
  host: string;
  method: string;
  url: string;
  path: string;
  status: number | null;
  size: number | null;
  duration_ms: number | null;
  tls_verify: boolean | null;
  ok: boolean;
  error_type: string | null;
  error_message: string | null;
}
export interface TrafficRun {
  domain: string;
  run_id: string;
  modified: number;
}
export interface Traffic {
  run: TrafficRun | null;
  flows: TrafficFlow[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  facets: { methods: string[]; statuses: number[]; modules: string[] };
  available_runs: TrafficRun[];
}
export interface TrafficParams {
  scan_id?: string;
  run_id?: string;
  host?: string;
  method?: string;
  status?: string;
  q?: string;
  module?: string;
  errors_only?: boolean;
  size_min?: number;
  size_max?: number;
  page?: number;
  page_size?: number;
}
export const getTraffic = (params: TrafficParams = {}) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === false) continue;
    qs.set(k, String(v));
  }
  const q = qs.toString();
  return apiFetch<Traffic>("/api/traffic" + (q ? `?${q}` : ""));
};

// ── Findings (cross-task vulnerability overview + operator triage) ────────────
export interface FindingTask {
  scan_id: string;
  domain: string;
  mode?: string | null;
}
export interface Finding {
  id: string;
  host: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  detected_status: string | null;
  status: string | null;
  verification_override: string | null;
  report_stage: string;
  note: string | null;
  confidence: number | null;
  confidence_label: string | null;
  detection_method: string | null;
  tier: string | null;
  references?: unknown;
  remediation: string | null;
  url: string | null;
  check_id: string | null;
  task: FindingTask;
  created_at: string | null;
  triaged_at: string | null;
}
export interface Findings {
  findings: Finding[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_stage: Record<string, number>;
    by_status: Record<string, number>;
  };
  facets: { categories: string[]; statuses: string[]; stages: string[]; tasks: FindingTask[] };
}
export interface FindingsParams {
  scan_id?: string;
  severity?: string;
  report_stage?: string;
  status?: string;
  category?: string;
  host?: string;
  q?: string;
  sort?: string;
  page?: number;
  page_size?: number;
}
function findingsQuery(params: FindingsParams): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    qs.set(k, String(v));
  }
  const q = qs.toString();
  return q ? `?${q}` : "";
}
export const getFindings = (params: FindingsParams = {}) =>
  apiFetch<Findings>("/api/findings" + findingsQuery(params));
export const patchTriage = (
  id: string,
  body: { report_stage?: string; note?: string; verification_override?: string }
) => apiFetch<{ ok: boolean; error?: string }>(`/api/findings/${id}/triage`, {
  method: "PATCH",
  body: JSON.stringify(body),
});
export async function exportFindings(params: FindingsParams = {}): Promise<void> {
  const token = getToken();
  const res = await fetch("/api/findings/export" + findingsQuery(params), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new ApiError(res.status, "export failed");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "findings.csv";
  a.click();
  URL.revokeObjectURL(url);
}

// ── Skills (agent-skill library, SKILL.md) ───────────────────────────────────
export interface SkillStats {
  total_calls: number;
  tasks_covered: number;
  last_called: string | null;
}
export interface SkillSummary {
  name: string;
  description: string;
  path: string;
  version: string | null;
  roles: string[];
  allowed_tools: string[];
  linked_mcp: string[];
  capabilities: string[];
  triggers: string[];
  tags: string[];
  resources: string[];
  summary: string;
  updated_at: number;
  error: string | null;
  stats: SkillStats;
}
export interface SkillDetail extends SkillSummary {
  body: string;
  roles_all: string[];
}
export interface SkillList {
  root: string;
  count: number;
  roles: string[];
  skills: SkillSummary[];
}
export interface SkillCreateBody {
  name: string;
  description?: string;
  body?: string;
  roles?: string[];
  allowed_tools?: string[];
  linked_mcp?: string[];
  capabilities?: string[];
  tags?: string[];
  overwrite?: boolean;
}
export const getSkills = () => apiFetch<SkillList>("/api/skills");
export const getSkill = (name: string) =>
  apiFetch<SkillDetail>(`/api/skills/${encodeURIComponent(name)}`);
export const createSkill = (body: SkillCreateBody) =>
  apiFetch<{ ok: boolean; name?: string }>("/api/skills", {
    method: "POST",
    body: JSON.stringify(body),
  });
export const patchSkill = (
  name: string,
  body: { roles?: string[]; description?: string; tags?: string[]; capabilities?: string[] }
) => apiFetch<{ ok: boolean; roles?: string[] }>(`/api/skills/${encodeURIComponent(name)}`, {
  method: "PATCH",
  body: JSON.stringify(body),
});

// ── Tool-execution mindmap ────────────────────────────────────────────────────
export type ExecKind = "scan" | "tool" | "etype";
export interface ExecNode {
  id: string;
  kind: ExecKind;
  label: string;
  count?: number;
  hosts?: number;
  state?: string | null;
  etype?: string;
  tools?: number;
  events?: number;
}
export interface ExecEdge {
  id: string;
  source: string;
  target: string;
}
export interface ExecMap {
  scan: { scan_id: string; domain: string; status: string; mode: string } | null;
  nodes: ExecNode[];
  edges: ExecEdge[];
  summary: { tools: number; events: number; event_types: number; by_tool: Record<string, number> };
}
export const getExecMap = (scanId?: string) =>
  apiFetch<ExecMap>("/api/execmap" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""));

// ── Exploration graph (reasoning map) ─────────────────────────────────────────
export type ExploreKind = "start" | "goal" | "intent" | "fact" | "vulnerability";
export type ExploreRel = "spawns" | "intent-chain" | "yields" | "proves";
export interface ExploreNode {
  id: string;
  kind: ExploreKind;
  label: string;
  count?: number;
  hosts?: number;
  state?: string | null;
  seed?: boolean;
  etype?: string;
  severity?: string;
  category?: string;
  host?: string;
  mode?: string | null;
  status?: string | null;
  intents?: number;
  events?: number;
}
export interface ExploreEdge {
  id: string;
  source: string;
  target: string;
  rel: ExploreRel;
}
export interface ExplorationMap {
  scan: { scan_id: string; domain: string; status: string; mode: string } | null;
  nodes: ExploreNode[];
  edges: ExploreEdge[];
  summary: { intents: number; facts: number; vulnerabilities: number; events: number };
}
export const getExploration = (scanId?: string) =>
  apiFetch<ExplorationMap>(
    "/api/exploration" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "")
  );
