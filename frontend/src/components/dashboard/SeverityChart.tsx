import { useNavigate } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid,
} from "recharts";
import { EmptyState } from "@/components/common/states";
import { ShieldAlert } from "lucide-react";

export const SEV_COLOR: Record<string, string> = {
  critical: "hsl(0 84% 60%)",
  high: "hsl(16 88% 58%)",
  medium: "hsl(38 92% 50%)",
  low: "hsl(142 71% 45%)",
  info: "hsl(215 20% 60%)",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

/** Vulnerability-severity distribution. Clicking a bar jumps to the vuln page. */
export function SeverityChart({ severity }: { severity: Record<string, number> }) {
  const navigate = useNavigate();
  const data = SEV_ORDER.filter((s) => severity[s]).map((s) => ({ name: s, value: severity[s] }));

  if (data.length === 0)
    return <EmptyState icon={ShieldAlert} title="No findings yet" description="Severity breakdown appears once findings land." />;

  return (
    <ResponsiveContainer width="100%" height={210}>
      <BarChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -16 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(218 35% 21%)" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: "hsl(215 20% 65%)", fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fill: "hsl(215 20% 65%)", fontSize: 12 }} axisLine={false} tickLine={false} />
        <Tooltip
          cursor={{ fill: "hsl(218 42% 15% / 0.5)" }}
          contentStyle={{ background: "hsl(218 42% 15%)", border: "1px solid hsl(218 35% 21%)", borderRadius: 10, fontSize: 12 }}
          labelStyle={{ color: "hsl(214 50% 93%)", textTransform: "capitalize" }}
        />
        <Bar dataKey="value" radius={[5, 5, 0, 0]} cursor="pointer"
          onClick={() => navigate("/vulnerabilities")}>
          {data.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name] ?? SEV_COLOR.info} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
