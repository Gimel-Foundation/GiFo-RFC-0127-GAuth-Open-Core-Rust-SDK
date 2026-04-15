import {
  useListMandates,
  useActivateMandate,
  useSuspendMandate,
  useResumeMandate,
  useRevokeMandate,
  getListMandatesQueryKey,
  type MandateStatus,
  type GovernanceProfile,
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { useState } from "react";
import { format } from "date-fns";
import { Play, Pause, ShieldOff, ChevronLeft, ChevronRight, AlertCircle } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";

const STATUS_TABS = ["all", "DRAFT", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"] as const;

export default function MandatesPage() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [subjectFilter, setSubjectFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const params = {
    limit: 20,
    cursor,
    status: statusFilter !== "all" ? (statusFilter as MandateStatus) : undefined,
  };

  const { data, isLoading, isError } = useListMandates(params);

  const activateMutation = useActivateMandate();
  const suspendMutation = useSuspendMandate();
  const resumeMutation = useResumeMandate();
  const revokeMutation = useRevokeMandate();

  const mandates = data?.items || [];

  const filteredMandates = mandates.filter((m: any) =>
    subjectFilter
      ? m.parties.subject.toLowerCase().includes(subjectFilter.toLowerCase())
      : true
  );

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

  const invalidateList = () => {
    queryClient.invalidateQueries({ queryKey: getListMandatesQueryKey(params) });
  };

  const handleAction = async (action: string, fn: () => Promise<unknown>) => {
    try {
      await fn();
      invalidateList();
      toast({ title: `Mandate ${action}d`, description: "Operation completed." });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      toast({ title: `Failed to ${action}`, description: message, variant: "destructive" });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">
          Mandates
        </h1>
        <p className="text-muted-foreground font-mono text-sm">
          Active and historical Power of Attorney authorizations.
        </p>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-border pb-0">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => {
              setStatusFilter(tab);
              setCursor(undefined);
            }}
            className={`px-3 py-2 text-xs font-mono uppercase transition-colors border-b-2 -mb-px ${
              statusFilter === tab
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      <Card className="bg-card border-border rounded-none shadow-none">
        <CardHeader className="border-b border-border pb-4 bg-secondary/30">
          <div className="flex gap-3">
            <Input
              placeholder="Filter by subject..."
              value={subjectFilter}
              onChange={(e) => setSubjectFilter(e.target.value)}
              className="rounded-none font-mono text-xs max-w-xs"
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-8 text-center text-primary font-mono animate-pulse uppercase">
              Loading mandates...
            </div>
          ) : isError ? (
            <div className="p-8 text-center">
              <AlertCircle className="h-8 w-8 text-destructive mx-auto mb-2" />
              <div className="font-mono text-destructive text-sm">Failed to load mandates</div>
            </div>
          ) : filteredMandates.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground font-mono text-sm">
              No mandates match current filters.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {filteredMandates.map((mandate: any) => (
                <div
                  key={mandate.mandate_id}
                  className="p-4 flex items-center justify-between hover:bg-secondary/30 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <Link
                        href={`/mandates/${mandate.mandate_id}`}
                        className="font-mono text-sm text-primary hover:underline truncate"
                      >
                        {mandate.mandate_id.split("-")[0]}...
                      </Link>
                      <Badge
                        variant="outline"
                        className={`rounded-none font-mono text-[10px] ${getStatusColor(mandate.status)}`}
                      >
                        {mandate.status}
                      </Badge>
                      <Badge
                        variant="outline"
                        className="rounded-none font-mono text-[10px] text-muted-foreground"
                      >
                        {mandate.governance_profile}
                      </Badge>
                    </div>
                    <div className="font-mono text-xs text-muted-foreground">
                      {mandate.parties.subject} · {format(new Date(mandate.created_at), "yyyy-MM-dd HH:mm")}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 ml-4">
                    {mandate.status === "DRAFT" && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="rounded-none h-7 w-7 p-0"
                        onClick={() =>
                          handleAction("activate", () =>
                            activateMutation.mutateAsync({ id: mandate.mandate_id })
                          )
                        }
                      >
                        <Play className="h-3 w-3 text-emerald-500" />
                      </Button>
                    )}
                    {mandate.status === "ACTIVE" && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="rounded-none h-7 w-7 p-0"
                        onClick={() =>
                          handleAction("suspend", () =>
                            suspendMutation.mutateAsync({
                              id: mandate.mandate_id,
                              data: { reason: "Suspended via dashboard" },
                            })
                          )
                        }
                      >
                        <Pause className="h-3 w-3 text-amber-500" />
                      </Button>
                    )}
                    {mandate.status === "SUSPENDED" && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="rounded-none h-7 w-7 p-0"
                        onClick={() =>
                          handleAction("resume", () =>
                            resumeMutation.mutateAsync({ id: mandate.mandate_id })
                          )
                        }
                      >
                        <Play className="h-3 w-3 text-emerald-500" />
                      </Button>
                    )}
                    {["DRAFT", "ACTIVE", "SUSPENDED"].includes(mandate.status) && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="rounded-none h-7 w-7 p-0"
                        onClick={() =>
                          handleAction("revoke", () =>
                            revokeMutation.mutateAsync({
                              id: mandate.mandate_id,
                              data: { reason: "Revoked via dashboard" },
                            })
                          )
                        }
                      >
                        <ShieldOff className="h-3 w-3 text-destructive" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {data?.next_cursor && (
            <div className="p-3 border-t border-border flex justify-between items-center">
              <Button
                size="sm"
                variant="outline"
                className="rounded-none font-mono text-xs"
                onClick={() => setCursor(undefined)}
                disabled={!cursor}
              >
                <ChevronLeft className="h-3 w-3 mr-1" /> First
              </Button>
              <span className="font-mono text-xs text-muted-foreground">
                {data.total} total
              </span>
              <Button
                size="sm"
                variant="outline"
                className="rounded-none font-mono text-xs"
                onClick={() => setCursor(data.next_cursor!)}
              >
                Next <ChevronRight className="h-3 w-3 ml-1" />
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
