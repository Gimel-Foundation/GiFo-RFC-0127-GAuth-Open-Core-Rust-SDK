import { useListMandates, useMgmtHealth } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, ShieldCheck, ShieldAlert, FileText, Clock, AlertTriangle } from "lucide-react";
import { Link } from "wouter";
import { formatDistanceToNow } from "date-fns";

export default function Dashboard() {
  const { data: mandatesData, isLoading } = useListMandates({ limit: 100 });
  const { data: health } = useMgmtHealth();

  const mandates = mandatesData?.items || [];

  const stats = {
    total: mandates.length,
    active: mandates.filter((m: any) => m.status === "ACTIVE").length,
    suspended: mandates.filter((m: any) => m.status === "SUSPENDED").length,
    draft: mandates.filter((m: any) => m.status === "DRAFT").length,
    revoked: mandates.filter((m: any) => m.status === "REVOKED").length,
    expired: mandates.filter((m: any) => m.status === "EXPIRED").length,
  };

  const recentMandates = [...mandates]
    .sort(
      (a: any, b: any) =>
        new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
    )
    .slice(0, 5);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "ACTIVE":
        return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
      case "DRAFT":
        return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "SUSPENDED":
        return "bg-amber-500/10 text-amber-500 border-amber-500/20";
      case "REVOKED":
        return "bg-destructive/10 text-destructive border-destructive/20";
      case "EXPIRED":
        return "bg-muted text-muted-foreground border-border";
      default:
        return "bg-secondary text-secondary-foreground border-border";
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">
          Global Overview
        </h1>
        <p className="text-muted-foreground font-mono text-sm">
          System-wide mandate activity and governance status.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono text-muted-foreground uppercase flex items-center justify-between">
              Total Mandates
              <FileText className="h-4 w-4 text-primary" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">
              {isLoading ? "-" : stats.total}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-emerald-500">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono text-muted-foreground uppercase flex items-center justify-between">
              Active Operations
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-emerald-500">
              {isLoading ? "-" : stats.active}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none border-t-2 border-t-amber-500">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono text-muted-foreground uppercase flex items-center justify-between">
              Suspended / Revoked
              <ShieldAlert className="h-4 w-4 text-amber-500" />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-amber-500">
              {isLoading ? "-" : stats.suspended + stats.revoked}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="col-span-2 bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border pb-4">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-8 text-center text-muted-foreground font-mono text-sm">
                Loading telemetry...
              </div>
            ) : recentMandates.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground font-mono text-sm">
                No mandates found in system.
              </div>
            ) : (
              <div className="divide-y divide-border">
                {recentMandates.map((mandate: any) => (
                  <div
                    key={mandate.mandate_id}
                    className="p-4 flex items-center justify-between hover:bg-secondary/50 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-3">
                        <Link
                          href={`/mandates/${mandate.mandate_id}`}
                          className="font-mono text-sm text-primary hover:underline"
                        >
                          {mandate.mandate_id.split("-")[0]}...
                        </Link>
                        <Badge
                          variant="outline"
                          className={`rounded-none font-mono text-[10px] ${getStatusColor(mandate.status)}`}
                        >
                          {mandate.status}
                        </Badge>
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {mandate.parties.subject}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span className="font-mono text-[10px]">
                        {formatDistanceToNow(new Date(mandate.updated_at), {
                          addSuffix: true,
                        })}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border pb-4">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              System Status
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-4 font-mono text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">API</span>
              <Badge
                variant="outline"
                className="rounded-none text-[10px] text-emerald-500 border-emerald-500/20 bg-emerald-500/10"
              >
                {health?.status === "ok" ? "ONLINE" : "CHECKING..."}
              </Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Version</span>
              <span className="text-xs">{health?.version ?? "-"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">SDK</span>
              <span className="text-xs">{health?.sdk ?? "-"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Uptime</span>
              <span className="text-xs">
                {health?.uptime_seconds != null
                  ? `${Math.floor(health.uptime_seconds / 60)}m`
                  : "-"}
              </span>
            </div>
            <div className="border-t border-border pt-3">
              <div className="flex justify-between">
                <span className="text-muted-foreground text-xs uppercase">
                  Draft
                </span>
                <span className="text-xs text-blue-500">{stats.draft}</span>
              </div>
              <div className="flex justify-between mt-1">
                <span className="text-muted-foreground text-xs uppercase">
                  Active
                </span>
                <span className="text-xs text-emerald-500">{stats.active}</span>
              </div>
              <div className="flex justify-between mt-1">
                <span className="text-muted-foreground text-xs uppercase">
                  Suspended
                </span>
                <span className="text-xs text-amber-500">{stats.suspended}</span>
              </div>
              <div className="flex justify-between mt-1">
                <span className="text-muted-foreground text-xs uppercase">
                  Revoked
                </span>
                <span className="text-xs text-destructive">{stats.revoked}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
