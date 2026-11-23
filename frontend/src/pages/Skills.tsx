import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, FolderGit2, Check, FileText, Sparkles } from "lucide-react";
import { getSkills, getSkill, createSkill, patchSkill, type SkillCreateBody, type SkillDetail } from "@/lib/api";
import { useToast } from "@/components/ui/toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/field";
import { cn } from "@/lib/cn";

const CAPS = [
  "PASSIVE_EXTERNAL", "TARGET_DNS_QUERY", "TARGET_HTTP_REQUEST", "ACTIVE_DISCOVERY",
  "FUZZING", "PORT_SCANNING", "VULNERABILITY_CHECK", "INTRUSIVE_TEST",
];

export default function Skills() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string>("");
  const [creating, setCreating] = useState(false);

  const { data: list } = useQuery({ queryKey: ["skills"], queryFn: getSkills, refetchInterval: 15_000 });
  const skills = list?.skills ?? [];
  const roles = list?.roles ?? ["planner", "worker", "report", "retest"];

  useEffect(() => {
    if (!selected && skills.length && !creating) setSelected(skills[0].name);
  }, [skills, selected, creating]);

  const { data: detail } = useQuery({
    queryKey: ["skill", selected],
    queryFn: () => getSkill(selected),
    enabled: !!selected && !creating,
  });

  const toast = useToast();
  const roleMut = useMutation({
    mutationFn: ({ name, roles }: { name: string; roles: string[] }) => patchSkill(name, { roles }),
    onSuccess: (_r, v) => {
      qc.invalidateQueries({ queryKey: ["skill", v.name] });
      qc.invalidateQueries({ queryKey: ["skills"] });
      toast.success("Visibility updated", `${v.name} · ${v.roles.length ? v.roles.join(", ") : "all roles"}`);
    },
    onError: () => toast.error("Could not update visibility"),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Skills</h1>
          <p className="text-xs text-muted-foreground">
            Skill library · SKILL.md spec · visibility granted per agent
            {list ? ` · ${list.count} skills` : ""}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[18rem_1fr]">
        {/* Left: list + create */}
        <div className="space-y-2">
          <Button variant="outline" className="w-full justify-center gap-1.5"
            onClick={() => { setCreating(true); setSelected(""); }}>
            <Plus className="h-4 w-4" /> Create skill
          </Button>
          <div className="overflow-hidden rounded-lg border border-border">
            {skills.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-muted-foreground">No skills yet.</p>
            ) : (
              skills.map((s) => (
                <button key={s.name}
                  onClick={() => { setCreating(false); setSelected(s.name); }}
                  className={cn("flex w-full items-start gap-2 border-b border-border/50 px-3 py-2 text-left last:border-0 transition-all duration-150",
                    selected === s.name && !creating ? "bg-accent" : "hover:translate-x-0.5 hover:bg-accent/50")}>
                  <FolderGit2 className="mt-0.5 h-4 w-4 shrink-0 text-primary/70" />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-foreground">{s.name}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{s.description || s.summary}</div>
                    {s.error && <div className="text-[11px] text-critical">parse error</div>}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Right: detail or create form */}
        <div key={creating ? "create" : selected || "none"} className="animate-fade-in">
          {creating ? (
            <CreateForm roles={roles}
              onCancel={() => setCreating(false)}
              onCreated={(name) => {
                setCreating(false);
                qc.invalidateQueries({ queryKey: ["skills"] });
                setSelected(name);
              }} />
          ) : detail ? (
            <Detail detail={detail} roles={roles}
              onToggleRole={(role) => {
                const cur = detail.roles.length ? detail.roles : roles; // empty = all
                const next = cur.includes(role) ? cur.filter((r) => r !== role) : [...cur, role];
                roleMut.mutate({ name: detail.name, roles: next });
              }} />
          ) : (
            <p className="animate-fade-in text-sm text-muted-foreground">Select a skill, or create one.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function Detail({ detail, roles, onToggleRole }: {
  detail: SkillDetail; roles: string[]; onToggleRole: (role: string) => void;
}) {
  const d = detail;
  const visible = (r: string) => d.roles.length === 0 || d.roles.includes(r);
  return (
    <div className="space-y-5 rounded-lg border border-border bg-panel p-5">
      <div>
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-semibold text-foreground">{d.name}</h2>
          {d.version && <Badge variant="outline" className="font-mono">v{d.version}</Badge>}
        </div>
        <p className="mt-1 text-sm text-muted-foreground">{d.description}</p>
        {d.tags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {d.tags.map((t) => <Badge key={t} variant="default">{t}</Badge>)}
          </div>
        )}
      </div>

      <div className="grid gap-5 md:grid-cols-[1fr_auto]">
        <div className="space-y-4">
          {(d.linked_mcp.length > 0 || d.allowed_tools.length > 0) && (
            <Section title="Linked tools / MCP" hint="unlocked only when the skill loads — intersected with the mode's capability ceiling">
              <div className="flex flex-wrap gap-1.5">
                {d.linked_mcp.map((m) => <Badge key={m} variant="outline">{m}</Badge>)}
                {d.allowed_tools.map((t) => <Badge key={t} variant="default" className="font-mono">{t}</Badge>)}
              </div>
            </Section>
          )}
          {d.capabilities.length > 0 && (
            <Section title="Capabilities" hint="never widens the mode — ceiling stays authoritative">
              <div className="flex flex-wrap gap-1.5">
                {d.capabilities.map((c) => <Badge key={c} variant="warning" className="font-mono">{c}</Badge>)}
              </div>
            </Section>
          )}
          <Section title="Visibility (granted per agent)" hint="click to toggle">
            <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
              {roles.map((r) => (
                <button key={r} onClick={() => onToggleRole(r)}
                  className={cn("flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors",
                    visible(r) ? "border-success/40 bg-success/10 text-success"
                               : "border-border text-muted-foreground hover:text-foreground")}>
                  {visible(r) ? <Check className="h-3.5 w-3.5" /> : <span className="h-3.5 w-3.5" />}
                  {r}
                </button>
              ))}
            </div>
            {d.roles.length === 0 && <p className="mt-1 text-[11px] text-muted-foreground">visible to all roles (none restricted)</p>}
          </Section>
          {d.triggers.length > 0 && (
            <Section title="When to use">
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
                {d.triggers.map((t, i) => <li key={i}>{t}</li>)}
              </ul>
            </Section>
          )}
        </div>

        {/* Call stats */}
        <div className="flex gap-3 md:flex-col">
          <StatBox label="Total calls" value={d.stats.total_calls} />
          <StatBox label="Tasks covered" value={d.stats.tasks_covered} />
          <div className="rounded-lg border border-border bg-card px-4 py-3 text-center">
            <div className="text-sm font-semibold text-foreground">
              {d.stats.last_called ? d.stats.last_called.slice(0, 10) : "Never called"}
            </div>
            <div className="text-[11px] text-muted-foreground">Last called</div>
          </div>
          <p className="max-w-[12rem] text-[11px] text-muted-foreground">
            Counts loads into the agent loop's context (per scan).
          </p>
        </div>
      </div>

      {/* Body */}
      <Section title="Instructions" icon={<FileText className="h-3.5 w-3.5" />}>
        <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap rounded-md border border-border bg-background/60 p-3 text-[12px] leading-relaxed text-foreground/90">
          {d.body || "(empty)"}
        </pre>
      </Section>

      {d.resources.length > 0 && (
        <Section title="Resources">
          <div className="flex flex-wrap gap-1.5">
            {d.resources.map((r) => <Badge key={r} variant="outline" className="font-mono">{r}</Badge>)}
          </div>
        </Section>
      )}
    </div>
  );
}

function CreateForm({ roles, onCancel, onCreated }: {
  roles: string[]; onCancel: () => void; onCreated: (name: string) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [bodyText, setBodyText] = useState("");
  const [tags, setTags] = useState("");
  const [pickedRoles, setPickedRoles] = useState<string[]>([]);
  const [caps, setCaps] = useState<string[]>([]);

  const nameValid = /^[a-z0-9][a-z0-9._-]{0,63}$/.test(name);
  const toast = useToast();

  const mut = useMutation({
    mutationFn: (b: SkillCreateBody) => createSkill(b),
    onSuccess: (r) => {
      if (r.ok && r.name) {
        toast.success("Skill created", r.name);
        onCreated(r.name);
      } else {
        toast.error("Could not create skill", (r as { error?: string }).error || "unknown error");
      }
    },
    onError: () => toast.error("Could not create skill"),
  });

  const toggle = (list: string[], v: string, set: (x: string[]) => void) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <div className="space-y-4 rounded-lg border border-border bg-panel p-5">
      <div className="flex items-center gap-2">
        <Sparkles className="h-5 w-5 text-primary" />
        <h2 className="text-lg font-semibold">Create skill</h2>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Name (slug)</span>
          <Input value={name} onChange={(e) => setName(e.target.value.toLowerCase())} placeholder="hunt-ssrf" className="font-mono" />
          {name && !nameValid && <span className="text-[11px] text-critical">a-z, 0-9, -, _, . only</span>}
        </label>
        <label className="space-y-1">
          <span className="text-xs text-muted-foreground">Tags (comma-separated)</span>
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="ssrf, web" />
        </label>
      </div>

      <label className="block space-y-1">
        <span className="text-xs text-muted-foreground">Description (what + when to use)</span>
        <Input value={description} onChange={(e) => setDescription(e.target.value)}
          placeholder="Hunt SSRF on endpoints that fetch a URL. Use when a parameter takes a URL/host." />
      </label>

      <div className="space-y-1">
        <span className="text-xs text-muted-foreground">Visibility (roles)</span>
        <div className="flex flex-wrap gap-1.5">
          {roles.map((r) => (
            <button key={r} onClick={() => toggle(pickedRoles, r, setPickedRoles)}
              className={cn("rounded-md border px-2.5 py-1 text-xs transition-colors",
                pickedRoles.includes(r) ? "border-success/40 bg-success/10 text-success" : "border-border text-muted-foreground hover:text-foreground")}>
              {r}
            </button>
          ))}
          <span className="self-center text-[11px] text-muted-foreground">none = all roles</span>
        </div>
      </div>

      <div className="space-y-1">
        <span className="text-xs text-muted-foreground">Capabilities (gated by mode ceiling)</span>
        <div className="flex flex-wrap gap-1.5">
          {CAPS.map((c) => (
            <button key={c} onClick={() => toggle(caps, c, setCaps)}
              className={cn("rounded-md border px-2 py-0.5 font-mono text-[11px] transition-colors",
                caps.includes(c) ? "border-warning/40 bg-warning/10 text-warning" : "border-border text-muted-foreground hover:text-foreground")}>
              {c}
            </button>
          ))}
        </div>
      </div>

      <label className="block space-y-1">
        <span className="text-xs text-muted-foreground">Instructions (markdown)</span>
        <textarea value={bodyText} onChange={(e) => setBodyText(e.target.value)} rows={10}
          className="w-full rounded-md border border-border bg-background/60 p-3 font-mono text-xs text-foreground outline-none focus:border-primary"
          placeholder={"# Hunt SSRF\n\nGoal: …\n\n## Method\n1. …"} />
      </label>

      {mut.isError && <p className="text-xs text-critical">Create failed — name may already exist.</p>}

      <div className="flex gap-2">
        <Button disabled={!nameValid || mut.isPending}
          onClick={() => mut.mutate({
            name, description, body: bodyText,
            roles: pickedRoles.length ? pickedRoles : undefined,
            capabilities: caps.length ? caps : undefined,
            tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
          })}>
          {mut.isPending ? "Creating…" : "Create skill"}
        </Button>
        <Button variant="outline" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  );
}

function Section({ title, hint, icon, children }: {
  title: string; hint?: string; icon?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {icon} {title}
        {hint && <span className="ml-1 font-normal normal-case text-muted-foreground/60">· {hint}</span>}
      </div>
      {children}
    </div>
  );
}

function StatBox({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3 text-center">
      <div className="text-2xl font-semibold tabular-nums text-foreground">{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}
