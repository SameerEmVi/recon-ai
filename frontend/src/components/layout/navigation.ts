import {
  LayoutDashboard, Crosshair, Activity, Server, Share2, ShieldAlert, Bug,
  Network, Radio, Workflow, ListChecks, Sparkles, ScrollText, Settings, ShieldCheck,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Exact-match the index route. */
  end?: boolean;
  /** Extra words the command palette matches on. */
  keywords?: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

/**
 * Grouped primary navigation. Every destination maps to a REAL route in
 * App.tsx — items from the design brief that have no route yet (DNS &
 * Subdomains, Integrations) are intentionally omitted rather than shipped as
 * dead links. Shared by the Sidebar, the Breadcrumbs, and the command palette
 * so the three can never drift.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Command",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard, end: true, keywords: "dashboard home command centre" },
      { to: "/scans", label: "Scan Management", icon: Crosshair, keywords: "new scan launch start" },
      { to: "/monitor", label: "Live Operations", icon: Activity, keywords: "monitor live events stream telemetry" },
    ],
  },
  {
    label: "Attack Surface",
    items: [
      { to: "/assets", label: "Asset Explorer", icon: Server, keywords: "hosts subdomains ip services" },
      { to: "/map", label: "Attack Surface Graph", icon: Share2, keywords: "asset map graph topology" },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, keywords: "vulns cve severity" },
      { to: "/findings", label: "Findings & Triage", icon: Bug, keywords: "findings triage report verification" },
      { to: "/pentest", label: "Pentest", icon: ShieldCheck, keywords: "pentest assess evidence authorization retest" },
      { to: "/exploration", label: "Exploration Graph", icon: Network, keywords: "reasoning graph intents facts" },
    ],
  },
  {
    label: "Analysis",
    items: [
      { to: "/traffic", label: "HTTP Traffic", icon: Radio, keywords: "requests responses http inspector" },
      { to: "/execmap", label: "Tool Execution", icon: Workflow, keywords: "tools modules execution map" },
      { to: "/diagnostics", label: "Diagnostics", icon: ScrollText, keywords: "logs errors debug proxy" },
    ],
  },
  {
    label: "AI Workspace",
    items: [
      { to: "/plan", label: "Agent Plans", icon: ListChecks, keywords: "plan progress agent steps" },
      { to: "/skills", label: "Skill Library", icon: Sparkles, keywords: "skills methodology agent" },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/settings", label: "Configuration", icon: Settings, keywords: "settings token config integrations" },
    ],
  },
];

export const ALL_NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

/** Longest-prefix match of a pathname to a nav item (for breadcrumb/active). */
export function navItemForPath(pathname: string): NavItem | undefined {
  if (pathname === "/") return ALL_NAV_ITEMS.find((i) => i.to === "/");
  const matches = ALL_NAV_ITEMS
    .filter((i) => i.to !== "/" && pathname.startsWith(i.to))
    .sort((a, b) => b.to.length - a.to.length);
  return matches[0];
}
