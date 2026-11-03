import { useState, type ReactNode } from "react";
import { Crosshair } from "lucide-react";
import { getToken, setToken } from "@/lib/auth";
import { Button } from "@/components/ui/button";

/** Gate the app behind the local bearer token. The backend is the real
 * authority; this just captures the token the server printed at startup. */
export function TokenGate({ children }: { children: ReactNode }) {
  const [token, setLocal] = useState<string | null>(getToken());
  const [draft, setDraft] = useState("");

  if (token) return <>{children}</>;

  return (
    <div className="flex h-full items-center justify-center p-6">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!draft.trim()) return;
          setToken(draft);
          setLocal(draft.trim());
        }}
        className="w-full max-w-sm rounded-lg border border-border bg-card p-6"
      >
        <div className="mb-4 flex items-center gap-2">
          <Crosshair className="h-5 w-5 text-primary" />
          <span className="font-mono text-sm font-semibold tracking-widest">
            RECON<span className="text-primary">-AI</span>
          </span>
        </div>
        <label className="mb-1 block text-xs text-muted-foreground" htmlFor="token">
          Access token
        </label>
        <input
          id="token"
          type="password"
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Paste the token printed by recon-ai-web"
          className="mb-3 w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
        />
        <Button type="submit" className="w-full">
          Unlock
        </Button>
        <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
          The server prints a token on startup (or set <code>RECON_AI_WEB_TOKEN</code>).
          Stored locally in this browser only.
        </p>
      </form>
    </div>
  );
}
