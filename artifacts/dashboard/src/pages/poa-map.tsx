import { useListMandates } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Lock,
  Unlock,
  Eye,
  ChevronDown,
  ChevronRight,
  Globe,
  Scale,
  AlertCircle,
} from "lucide-react";
import { useState } from "react";

function PermissionCard({ mandate }: { mandate: any }) {
  const [expanded, setExpanded] = useState(false);

  const coreVerbs = mandate.scope?.core_verbs ?? {};
  const allowedSectors = mandate.scope?.allowed_sectors ?? [];
  const allowedRegions = mandate.scope?.allowed_regions ?? [];
  const allowedDecisions = mandate.scope?.allowed_decisions ?? [];
  const allowedPaths = mandate.scope?.allowed_paths ?? [];
  const deniedPaths = mandate.scope?.denied_paths ?? [];

  const allowedVerbs = Object.entries(coreVerbs).filter(
    ([, p]: [string, any]) => p.allowed !== false
  );
  const deniedVerbs = Object.entries(coreVerbs).filter(
    ([, p]: [string, any]) => p.allowed === false
  );
  const approvalRequired = Object.entries(coreVerbs).filter(
    ([, p]: [string, any]) => p.requires_approval
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
      default:
        return "bg-muted text-muted-foreground border-border";
    }
  };

  return (
    <Card className="bg-card border-border rounded-none shadow-none">
      <CardHeader
        className="cursor-pointer border-b border-border bg-secondary/10 py-3"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {expanded ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <div>
              <div className="font-mono text-sm font-bold text-primary">
                {mandate.mandate_id.split("-")[0]}...
              </div>
              <div className="font-mono text-xs text-muted-foreground">
                {mandate.parties.subject}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
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
        </div>
      </CardHeader>
      {expanded && (
        <CardContent className="p-4 space-y-4">
          <div>
            <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
              <Unlock className="h-3 w-3 text-emerald-500" /> Allowed Verbs ({allowedVerbs.length})
            </div>
            <div className="flex flex-wrap gap-1.5">
              {allowedVerbs.length > 0 ? (
                allowedVerbs.map(([verb, policy]: [string, any]) => (
                  <Badge
                    key={verb}
                    variant="outline"
                    className="rounded-none font-mono text-[10px] text-emerald-500 border-emerald-500/30 bg-emerald-500/5"
                  >
                    {verb}
                    {policy.max_per_session != null && ` (max:${policy.max_per_session})`}
                  </Badge>
                ))
              ) : (
                <span className="text-xs font-mono text-muted-foreground">None defined</span>
              )}
            </div>
          </div>

          {deniedVerbs.length > 0 && (
            <div>
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Lock className="h-3 w-3 text-destructive" /> Denied Verbs ({deniedVerbs.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {deniedVerbs.map(([verb]) => (
                  <Badge
                    key={verb}
                    variant="outline"
                    className="rounded-none font-mono text-[10px] text-destructive border-destructive/30 bg-destructive/5"
                  >
                    {verb}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {approvalRequired.length > 0 && (
            <div>
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Eye className="h-3 w-3 text-amber-500" /> Requires Approval (
                {approvalRequired.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {approvalRequired.map(([verb]) => (
                  <Badge
                    key={verb}
                    variant="outline"
                    className="rounded-none font-mono text-[10px] text-amber-500 border-amber-500/30 bg-amber-500/5"
                  >
                    {verb}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {allowedDecisions.length > 0 && (
            <div className="border-t border-border pt-3">
              <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                <Scale className="h-3 w-3" /> Allowed Decisions ({allowedDecisions.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allowedDecisions.map((d: string) => (
                  <Badge
                    key={d}
                    variant="outline"
                    className="rounded-none font-mono text-[10px]"
                  >
                    {d}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {(allowedRegions.length > 0 || allowedSectors.length > 0) && (
            <div className="border-t border-border pt-3 grid grid-cols-2 gap-4">
              {allowedRegions.length > 0 && (
                <div>
                  <div className="text-xs font-mono text-muted-foreground uppercase mb-2 flex items-center gap-1">
                    <Globe className="h-3 w-3" /> Regions
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {allowedRegions.map((r: string) => (
                      <Badge
                        key={r}
                        variant="outline"
                        className="rounded-none font-mono text-[10px]"
                      >
                        {r}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {allowedSectors.length > 0 && (
                <div>
                  <div className="text-xs font-mono text-muted-foreground uppercase mb-2">
                    Sectors
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {allowedSectors.map((s: string) => (
                      <Badge
                        key={s}
                        variant="outline"
                        className="rounded-none font-mono text-[10px]"
                      >
                        {s}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {(allowedPaths.length > 0 || deniedPaths.length > 0) && (
            <div className="border-t border-border pt-3">
              {allowedPaths.length > 0 && (
                <div className="mb-2">
                  <div className="text-xs font-mono text-muted-foreground uppercase mb-1">
                    Allowed Paths
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {allowedPaths.map((p: string) => (
                      <Badge
                        key={p}
                        variant="outline"
                        className="rounded-none font-mono text-[10px] text-emerald-500 border-emerald-500/30"
                      >
                        {p}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {deniedPaths.length > 0 && (
                <div>
                  <div className="text-xs font-mono text-muted-foreground uppercase mb-1">
                    Denied Paths
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {deniedPaths.map((p: string) => (
                      <Badge
                        key={p}
                        variant="outline"
                        className="rounded-none font-mono text-[10px] text-destructive border-destructive/30"
                      >
                        {p}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

export default function PoaMapPage() {
  const { data, isLoading, isError } = useListMandates({ limit: 100 });

  const mandates = data?.items || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">
          PoA Permission Map
        </h1>
        <p className="text-muted-foreground font-mono text-sm">
          Expanded view of each mandate's scope, verbs, and constraints.
        </p>
      </div>

      {isLoading ? (
        <div className="p-8 text-center text-primary font-mono animate-pulse uppercase">
          Loading permissions...
        </div>
      ) : isError ? (
        <div className="p-8 text-center">
          <AlertCircle className="h-12 w-12 text-destructive mx-auto mb-4" />
          <div className="font-mono text-destructive">Failed to load mandates</div>
        </div>
      ) : mandates.length === 0 ? (
        <div className="p-8 text-center text-muted-foreground font-mono text-sm">
          No mandates in system.
        </div>
      ) : (
        <div className="space-y-3">
          {mandates.map((mandate: any) => (
            <PermissionCard key={mandate.mandate_id} mandate={mandate} />
          ))}
        </div>
      )}
    </div>
  );
}
