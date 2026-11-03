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
export const getDiagnostics = (params: { domain?: string; run_id?: string; stream?: string; module?: string } = {}) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
  const q = qs.toString();
  return apiFetch<Diagnostics>("/api/diagnostics" + (q ? `?${q}` : ""));
};
export const checkProxy = (url: string) =>
  apiFetch<ProxyCheck>("/api/diagnostics/proxy-check", { method: "POST", body: JSON.stringify({ url }) });
export const getConfig = () => apiFetch<AppConfig>("/api/config");
