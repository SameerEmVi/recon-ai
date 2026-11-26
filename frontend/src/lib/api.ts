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
  ai: { available: boolean };
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
  ai?: boolean;
  agent?: boolean;
  max_iterations?: number;
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
// Left-to-right plan: start/scope → goals (one per capability tier, processed in
// order) → intents (tools) → facts / vulnerabilities. See api/exploration.py.
export type ExploreKind = "start" | "scope" | "goal" | "intent" | "fact" | "vulnerability";
export type ExploreRel = "spawns" | "next" | "constrains" | "intent-chain" | "yields" | "proves";
export type ExploreTier = "osint" | "recon" | "pentest";
export interface ExploreNode {
  id: string;
  kind: ExploreKind;
  label: string;
  summary?: string;
  state?: string;
  priority?: number;
  tier?: ExploreTier;
  step?: number;            // goal: 1-based processing order
  order?: number;           // intent: order within its goal (chronological)
  count?: number;
  hosts?: number;
  intents?: number;
  events?: number;
  done?: number;
  reason?: string;          // goal: why it is locked
  caps?: string[];
  seed?: boolean;
  first_seen?: string;
  last_seen?: string;
  failed_jobs?: number;
  fed_by?: string[];
  feeds?: string[];
  more_facts?: number;
  etype?: string;
  samples?: string[];
  severity?: string;
  category?: string;
  host?: string;
  verification?: string;
  confidence?: number;
  mode?: string | null;
  status?: string | null;
  in_scope?: string[];
  out_scope?: string[];
  max_distance?: number;
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
  summary: {
    goals: number;
    goals_achieved: number;
    intents: number;
    facts: number;
    vulnerabilities: number;
    events: number;
  };
}
export const getExploration = (scanId?: string) =>
  apiFetch<ExplorationMap>(
    "/api/exploration" + (scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "")
  );

// ── Autonomous exploration engine (goal/intent/fact) ──────────────────────────
export interface EngRun {
  id: string; scan_id: string; title: string; target: string; status: string;
  constraints: unknown; stop_reason: string | null; created_at: string | null;
}
export interface EngGoal {
  id: string; parent_goal_id: string | null; title: string; description: string;
  success_criteria: unknown; priority: number; state: string;
  completion_reason: string | null; created_by: string; created_at: string | null;
}
export interface EngIntent {
  id: string; goal_id: string; title: string; tool_name: string; target: string;
  rationale: string; priority: number; required_capability: string | null; state: string;
  approval_state: string; execution_summary: string | null; error: string | null;
  created_at: string | null; completed_at: string | null;
}
export interface EngFact {
  id: string; goal_id: string | null; intent_id: string | null; asset: string;
  fact_type: string; title: string; content: unknown; confidence: number; source: string;
  source_event_id: string | null; evidence_reference: string | null; created_at: string | null;
}
export interface EngActivity {
  id: string; node_id: string | null; worker: string; activity_type: string;
  tool_name: string | null; summary: string; data: unknown; timestamp: string | null;
}
export interface EngRound {
  round_no: number; trigger: string; status: string; decision_summary: string | null;
  operations_count: number; started_at: string | null; completed_at: string | null;
}
export type EngNodeKind = "objective" | "goal" | "intent" | "fact" | "hint" | "finding" | "digest";
export interface EngNode {
  id: string; kind: EngNodeKind; label: string; state?: string; priority?: number;
  tool?: string; fact_type?: string; confidence?: number; count?: number;
}
export interface EngEdge { id: string; source: string; target: string; rel: string }
export interface EngGraph {
  run: EngRun | null; nodes: EngNode[]; edges: EngEdge[];
  summary: { goals: number; intents: number; facts: number; by_kind: Record<string, number> };
  truncated: boolean;
}

const engQ = (scanId?: string, explorationId?: string): string => {
  const p = new URLSearchParams();
  if (scanId) p.set("scan_id", scanId);
  if (explorationId) p.set("exploration_id", explorationId);
  const s = p.toString();
  return s ? `?${s}` : "";
};

export const listExplorations = () =>
  apiFetch<{ explorations: EngRun[] }>("/api/explorations");
export const getEngineGraph = (scanId?: string, eid?: string) =>
  apiFetch<EngGraph>("/api/exploration/engine-graph" + engQ(scanId, eid));
export const getEngGoals = (scanId?: string, eid?: string) =>
  apiFetch<{ run: EngRun | null; goals: EngGoal[] }>("/api/exploration/goals" + engQ(scanId, eid));
export const getEngIntents = (scanId?: string, eid?: string) =>
  apiFetch<{ run: EngRun | null; intents: EngIntent[] }>("/api/exploration/intents" + engQ(scanId, eid));
export const getEngFacts = (scanId?: string, eid?: string) =>
  apiFetch<{ run: EngRun | null; facts: EngFact[]; total: number }>("/api/exploration/facts" + engQ(scanId, eid));
export const getEngActivities = (scanId?: string, eid?: string) =>
  apiFetch<{ run: EngRun | null; activities: EngActivity[] }>("/api/exploration/activities" + engQ(scanId, eid));
export const getEngRounds = (scanId?: string, eid?: string) =>
  apiFetch<{ run: EngRun | null; rounds: EngRound[] }>("/api/exploration/rounds" + engQ(scanId, eid));
export const getEngNode = (nodeId: string, scanId?: string, eid?: string) =>
  apiFetch<Record<string, unknown>>(`/api/exploration/node/${nodeId}` + engQ(scanId, eid));

const engPost = (path: string, body?: unknown) =>
  apiFetch<{ ok?: boolean; status?: string; [k: string]: unknown }>(path,
    { method: "POST", ...(body ? { body: JSON.stringify(body) } : {}) });
export const engPause = (eid: string) => engPost(`/api/exploration/${eid}/pause`);
export const engResume = (eid: string) => engPost(`/api/exploration/${eid}/resume`);
export const engStop = (eid: string, reason?: string) => engPost(`/api/exploration/${eid}/stop`, { reason });
export const engReplan = (eid: string) => engPost(`/api/exploration/${eid}/replan`);
export const engApproveIntent = (eid: string, iid: string) => engPost(`/api/exploration/${eid}/intent/${iid}/approve`);
export const engRejectIntent = (eid: string, iid: string, reason?: string) => engPost(`/api/exploration/${eid}/intent/${iid}/reject`, { reason });
export const engCancelIntent = (eid: string, iid: string) => engPost(`/api/exploration/${eid}/intent/${iid}/cancel`);
export const engPrioritizeGoal = (eid: string, gid: string, priority: number) => engPost(`/api/exploration/${eid}/goal/${gid}/prioritize`, { priority });
export const engBlockGoal = (eid: string, gid: string, reason?: string) => engPost(`/api/exploration/${eid}/goal/${gid}/block`, { reason });

// ── Pentest section (manual, agent-driven assessment on a recon'd host) ───────────
export interface EvidenceExchange {
  id: string;
  finding_id: string | null;
  host: string;
  method: string;
  url: string;
  status_code: number | null;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  request_body: string | null;
  response_body: string | null;
  request_size: number | null;
  response_size: number | null;
  response_truncated: boolean;
  bodies_available: boolean;
  bodies_dropped: string | null;
  duration_ms: number | null;
  source_tool: string | null;
  created_at: string | null;
}
export interface PentestFinding {
  id: string;
  host: string;
  title: string;
  category: string;
  severity: string | null;
  evidence: EvidenceExchange[];
}
export interface AssessResult {
  ok: boolean;
  error?: string;
  url?: string;
  host?: string;
  summary?: string;
  findings_created?: number;
  findings?: PentestFinding[];
}
export const assessUrl = (scanId: string, url: string) =>
  apiFetch<AssessResult>("/api/pentest/assess", {
    method: "POST",
    body: JSON.stringify({ scan_id: scanId, url }),
  });

export interface EvidenceList {
  exchanges: EvidenceExchange[];
  count: number;
  key_available: boolean;
}
export const getEvidence = (params: { scanId?: string; findingId?: string }) => {
  const q = new URLSearchParams();
  if (params.scanId) q.set("scan_id", params.scanId);
  if (params.findingId) q.set("finding_id", params.findingId);
  const s = q.toString();
  return apiFetch<EvidenceList>("/api/evidence" + (s ? `?${s}` : ""));
};

export interface ReconScan { scan_id: string; domain: string; mode: string; status: string }
export const getPentestScans = () =>
  apiFetch<{ scans: ReconScan[] }>("/api/pentest/scans");

// Download the evidence-aware vulnerability report (Markdown by default).
export async function downloadReport(scanId: string, format: "md" | "html" | "json" | "text" = "md"): Promise<void> {
  const token = getToken();
  const res = await fetch(`/api/report?scan_id=${encodeURIComponent(scanId)}&format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new ApiError(res.status, "report export failed");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const ext = format === "json" ? "json" : format === "html" ? "html" : format === "md" ? "md" : "txt";
  const a = document.createElement("a");
  a.href = url;
  a.download = `recon-ai-report-${scanId.slice(0, 8)}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

export interface RetestResult {
  ok: boolean;
  error?: string;
  finding_id?: string;
  url?: string;
  outcome?: "reproducible" | "fixed";
  finding?: PentestFinding;
}
export const retestFinding = (scanId: string, findingId: string) =>
  apiFetch<RetestResult>("/api/pentest/retest", {
    method: "POST",
    body: JSON.stringify({ scan_id: scanId, finding_id: findingId }),
  });
