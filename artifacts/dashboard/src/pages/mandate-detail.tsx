import {
  useGetMandate,
  useGetMandateHistory,
  useGetDelegationChain,
  useActivateMandate,
  useSuspendMandate,
  useResumeMandate,
  useRevokeMandate,
  getGetMandateQueryKey,
  getGetMandateHistoryQueryKey,
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Clock,
  Play,
  Pause,
  ShieldOff,
  Activity,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Plus,
  Zap,
  Ban,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { Link, useParams } from "wouter";
import { format } from "date-fns";
import { useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

const ACTION_ICONS: Record<string, any> = {
  CREATED: Plus,
  ACTIVATED: Zap,
  SUSPENDED: Pause,
  RESUMED: RotateCcw,
  REVOKED: Ban,
};

export default function MandateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: mandate, isLoading, isError } = useGetMandate(id!);
  const { data: historyData } = useGetMandateHistory(id!);
  const { data: delegationData } = useGetDelegationChain(id!);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const activateMutation = useActivateMandate();
  const suspendMutation = useSuspendMandate();
  const resumeMutation = useResumeMandate();
  const revokeMutation = useRevokeMandate();

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: getGetMandateQueryKey(id!) });
    queryClient.invalidateQueries({ queryKey: getGetMandateHistoryQueryKey(id!) });
  };

  const handleAction = async (action: string, fn: () => Promise<unknown>) => {
    try {
      await fn();
      invalidate();
      toast({ title: `Mandate ${action}d`, description: "Operation completed." });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      toast({ title: `Failed to ${action}`, description: message, variant: "destructive" });
    }
  };

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
      default:
        return "bg-muted text-muted-foreground border-border";
    }
  };

  if (isLoading) {
    return (
      <div className="p-12 text-center font-mono text-primary animate-pulse uppercase">
        Loading mandate...
      </div>
    );
  }

  if (isError || !mandate) {
    return (
      <div className="p-12 text-center">
        <AlertTriangle className="h-12 w-12 text-destructive mx-auto mb-4" />
        <div className="font-mono text-destructive">Mandate not found</div>
        <Link href="/mandates" className="font-mono text-xs text-primary hover:underline mt-2 inline-block">
          Back to mandates
        </Link>
      </div>
    );
  }

  const m = mandate as any;
  const history = (historyData as any)?.entries || [];
  const chain = (delegationData as any)?.chain || [];
  const coreVerbs = m.scope?.core_verbs || {};
  const platformPerms = m.scope?.platform_permissions;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/mandates">
          <Button variant="ghost" size="sm" className="rounded-none h-8 w-8 p-0">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold font-mono text-foreground">
              {m.mandate_id.split("-")[0]}...
            </h1>
            <Badge
              variant="outline"
              className={`rounded-none font-mono text-[10px] ${getStatusColor(m.status)}`}
            >
              {m.status}
            </Badge>
            <Badge variant="outline" className="rounded-none font-mono text-[10px] text-muted-foreground">
              {m.governance_profile}
            </Badge>
          </div>
          <p className="font-mono text-xs text-muted-foreground mt-1">
            {m.parties.subject} — Created {format(new Date(m.created_at), "yyyy-MM-dd HH:mm")}
          </p>
        </div>
        <div className="flex gap-1">
          {m.status === "DRAFT" && (
            <Button
              size="sm"
              variant="outline"
              className="rounded-none font-mono text-xs"
              onClick={() =>
                handleAction("activate", () => activateMutation.mutateAsync({ id: m.mandate_id }))
              }
            >
              <Play className="h-3 w-3 mr-1" /> Activate
            </Button>
          )}
          {m.status === "ACTIVE" && (
            <Button
              size="sm"
              variant="outline"
              className="rounded-none font-mono text-xs"
              onClick={() =>
                handleAction("suspend", () =>
                  suspendMutation.mutateAsync({
                    id: m.mandate_id,
                    data: { reason: "Suspended via dashboard" },
                  })
                )
              }
            >
              <Pause className="h-3 w-3 mr-1" /> Suspend
            </Button>
          )}
          {m.status === "SUSPENDED" && (
            <Button
              size="sm"
              variant="outline"
              className="rounded-none font-mono text-xs"
              onClick={() =>
                handleAction("resume", () => resumeMutation.mutateAsync({ id: m.mandate_id }))
              }
            >
              <Play className="h-3 w-3 mr-1" /> Resume
            </Button>
          )}
          {["DRAFT", "ACTIVE", "SUSPENDED"].includes(m.status) && (
            <Button
              size="sm"
              variant="destructive"
              className="rounded-none font-mono text-xs"
              onClick={() =>
                handleAction("revoke", () =>
                  revokeMutation.mutateAsync({
                    id: m.mandate_id,
                    data: { reason: "Revoked via dashboard" },
                  })
                )
              }
            >
              <ShieldOff className="h-3 w-3 mr-1" /> Revoke
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border bg-secondary/10">
            <CardTitle className="font-mono uppercase text-sm">Parties</CardTitle>
          </CardHeader>
          <CardContent className="p-4 font-mono text-sm space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Grantor</span>
              <span className="text-xs">{m.parties.grantor}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Subject</span>
              <span className="text-xs">{m.parties.subject}</span>
            </div>
            {m.parties.intermediary && (
              <div className="flex justify-between">
                <span className="text-muted-foreground text-xs uppercase">Intermediary</span>
                <span className="text-xs">{m.parties.intermediary}</span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border bg-secondary/10">
            <CardTitle className="font-mono uppercase text-sm">Budget & Validity</CardTitle>
          </CardHeader>
          <CardContent className="p-4 font-mono text-sm space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Total Budget</span>
              <span className="text-xs">
                {m.budget?.total_cents != null ? `${(m.budget.total_cents / 100).toFixed(2)} EUR` : "Unlimited"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Remaining</span>
              <span className="text-xs">
                {m.budget?.remaining_cents != null
                  ? `${(m.budget.remaining_cents / 100).toFixed(2)} EUR`
                  : "—"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Valid From</span>
              <span className="text-xs">
                {m.valid_from ? format(new Date(m.valid_from), "yyyy-MM-dd HH:mm") : "—"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground text-xs uppercase">Valid Until</span>
              <span className="text-xs">
                {m.valid_until ? format(new Date(m.valid_until), "yyyy-MM-dd HH:mm") : "—"}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card border-border rounded-none shadow-none">
        <CardHeader className="border-b border-border bg-secondary/10">
          <CardTitle className="font-mono uppercase text-sm">Scope — Core Verbs</CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          {Object.keys(coreVerbs).length === 0 ? (
            <div className="font-mono text-xs text-muted-foreground">No verbs defined</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(coreVerbs).map(([verb, policy]: [string, any]) => (
                <Badge
                  key={verb}
                  variant="outline"
                  className={`rounded-none font-mono text-[10px] ${
                    policy.allowed === false
                      ? "text-destructive border-destructive/30 bg-destructive/5"
                      : policy.requires_approval
                        ? "text-amber-500 border-amber-500/30 bg-amber-500/5"
                        : "text-emerald-500 border-emerald-500/30 bg-emerald-500/5"
                  }`}
                >
                  {verb}
                  {policy.max_per_session != null && ` (max:${policy.max_per_session})`}
                  {policy.requires_approval && " ⚠"}
                  {policy.allowed === false && " ✕"}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-card border-border rounded-none shadow-none">
        <CardHeader className="border-b border-border bg-secondary/10">
          <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Audit History ({history.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {history.length === 0 ? (
            <div className="p-6 text-center font-mono text-xs text-muted-foreground">
              No history entries
            </div>
          ) : (
            <div className="divide-y divide-border">
              {history.map((entry: any) => {
                const Icon = ACTION_ICONS[entry.action] || Activity;
                return (
                  <div key={entry.id} className="p-3 flex items-start gap-3">
                    <div className="mt-0.5">
                      <Icon className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold uppercase">{entry.action}</span>
                        {entry.previous_status && entry.new_status && (
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {entry.previous_status} → {entry.new_status}
                          </span>
                        )}
                      </div>
                      {entry.reason && (
                        <div className="font-mono text-[10px] text-muted-foreground mt-0.5">
                          {entry.reason}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span className="font-mono text-[10px]">
                        {format(new Date(entry.timestamp), "HH:mm:ss")}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {chain.length > 0 && (
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border bg-secondary/10">
            <CardTitle className="font-mono uppercase text-sm">Delegation Chain</CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            <div className="space-y-2">
              {chain.map((node: any, i: number) => (
                <div
                  key={node.mandate_id}
                  className="flex items-center gap-3 font-mono text-xs"
                  style={{ paddingLeft: i * 20 }}
                >
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                  <span className="text-primary">{node.mandate_id.split("-")[0]}...</span>
                  <span className="text-muted-foreground">depth:{node.delegation_depth}</span>
                  <span className="text-muted-foreground">{node.delegate_agent_id}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
