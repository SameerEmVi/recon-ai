import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** A titled placeholder panel for pages whose content lands in a later increment. */
export function Placeholder({ title, note }: { title: string; note: string }) {
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
      <Card>
        <CardHeader>
          <CardTitle>Coming soon</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{note}</p>
        </CardContent>
      </Card>
    </div>
  );
}
