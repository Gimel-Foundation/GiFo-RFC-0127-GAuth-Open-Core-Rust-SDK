import { Router, type IRouter } from "express";
import { db } from "@workspace/db";
import { mandatesTable, auditEntriesTable } from "@workspace/db/schema";
import { eq, desc, sql, and, lt } from "drizzle-orm";
import {
  ListMandatesQueryParams,
  CreateMandateBody,
  GetMandateParams,
  ActivateMandateParams,
  SuspendMandateParams,
  SuspendMandateBody,
  ResumeMandateParams,
  RevokeMandateParams,
  RevokeMandateBody,
  GetMandateHistoryParams,
  GetDelegationChainParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

function serializeMandate(m: typeof mandatesTable.$inferSelect) {
  return {
    mandate_id: m.mandate_id,
    status: m.status,
    governance_profile: m.governance_profile,
    parties: m.parties,
    scope: m.scope,
    budget: m.budget ?? undefined,
    delegation: m.delegation ?? undefined,
    valid_from: m.valid_from?.toISOString() ?? null,
    valid_until: m.valid_until?.toISOString() ?? null,
    created_at: m.created_at.toISOString(),
    updated_at: m.updated_at.toISOString(),
  };
}

router.get("/mandates", async (req, res) => {
  try {
    const params = ListMandatesQueryParams.parse(req.query);
    const limit = params.limit ?? 20;
    const conditions = [];

    if (params.status) {
      conditions.push(eq(mandatesTable.status, params.status as any));
    }
    if (params.governance_profile) {
      conditions.push(eq(mandatesTable.governance_profile, params.governance_profile as any));
    }
    if (params.cursor) {
      conditions.push(lt(mandatesTable.created_at, new Date(params.cursor)));
    }

    const where = conditions.length > 0 ? and(...conditions) : undefined;

    const [items, countResult] = await Promise.all([
      db
        .select()
        .from(mandatesTable)
        .where(where)
        .orderBy(desc(mandatesTable.created_at))
        .limit(limit + 1),
      db
        .select({ count: sql<number>`count(*)::int` })
        .from(mandatesTable)
        .where(
          params.status || params.governance_profile
            ? and(
                ...[
                  params.status ? eq(mandatesTable.status, params.status as any) : undefined,
                  params.governance_profile ? eq(mandatesTable.governance_profile, params.governance_profile as any) : undefined,
                ].filter(Boolean) as any[]
              )
            : undefined
        ),
    ]);

    const hasMore = items.length > limit;
    const pageItems = hasMore ? items.slice(0, limit) : items;
    const nextCursor = hasMore ? pageItems[pageItems.length - 1].created_at.toISOString() : null;

    res.json({
      items: pageItems.map(serializeMandate),
      next_cursor: nextCursor,
      total: countResult[0].count,
    });
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

router.post("/mandates", async (req, res) => {
  try {
    const body = CreateMandateBody.parse(req.body);
    const [mandate] = await db
      .insert(mandatesTable)
      .values({
        governance_profile: (body as any).governance_profile ?? "standard",
        parties: body.parties as any,
        scope: body.scope as any,
        budget: (body as any).budget ?? null,
        delegation: (body as any).delegation ?? null,
        valid_from: (body as any).valid_from ? new Date((body as any).valid_from) : null,
        valid_until: (body as any).valid_until ? new Date((body as any).valid_until) : null,
      })
      .returning();

    await db.insert(auditEntriesTable).values({
      mandate_id: mandate.mandate_id,
      action: "CREATED",
      actor: "system",
      new_status: "DRAFT",
    });

    res.status(201).json(serializeMandate(mandate));
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

router.get("/mandates/:id", async (req, res) => {
  try {
    const { id } = GetMandateParams.parse(req.params);
    const [mandate] = await db
      .select()
      .from(mandatesTable)
      .where(eq(mandatesTable.mandate_id, id));

    if (!mandate) {
      res.status(404).json({ error: "Mandate not found" });
      return;
    }
    res.json(serializeMandate(mandate));
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

async function transitionMandate(
  id: string,
  fromStatuses: string[],
  toStatus: string,
  action: string,
  reason?: string
) {
  const [mandate] = await db
    .select()
    .from(mandatesTable)
    .where(eq(mandatesTable.mandate_id, id));

  if (!mandate) {
    return { error: "Mandate not found", status: 404 };
  }

  if (!fromStatuses.includes(mandate.status)) {
    return {
      error: `Cannot ${action.toLowerCase()} a mandate with status ${mandate.status}`,
      status: 409,
    };
  }

  const [updated] = await db
    .update(mandatesTable)
    .set({ status: toStatus as any, updated_at: new Date() })
    .where(eq(mandatesTable.mandate_id, id))
    .returning();

  await db.insert(auditEntriesTable).values({
    mandate_id: id,
    action,
    actor: "system",
    reason: reason ?? null,
    previous_status: mandate.status,
    new_status: toStatus,
  });

  return { data: serializeMandate(updated), status: 200 };
}

router.post("/mandates/:id/activate", async (req, res) => {
  const { id } = ActivateMandateParams.parse(req.params);
  const result = await transitionMandate(id, ["DRAFT"], "ACTIVE", "ACTIVATED");
  if (result.error) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.json(result.data);
});

router.post("/mandates/:id/suspend", async (req, res) => {
  const { id } = SuspendMandateParams.parse(req.params);
  const body = SuspendMandateBody.parse(req.body);
  const result = await transitionMandate(id, ["ACTIVE"], "SUSPENDED", "SUSPENDED", body.reason);
  if (result.error) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.json(result.data);
});

router.post("/mandates/:id/resume", async (req, res) => {
  const { id } = ResumeMandateParams.parse(req.params);
  const result = await transitionMandate(id, ["SUSPENDED"], "ACTIVE", "RESUMED");
  if (result.error) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.json(result.data);
});

router.post("/mandates/:id/revoke", async (req, res) => {
  const { id } = RevokeMandateParams.parse(req.params);
  const body = RevokeMandateBody.parse(req.body);
  const result = await transitionMandate(
    id,
    ["DRAFT", "ACTIVE", "SUSPENDED"],
    "REVOKED",
    "REVOKED",
    body.reason
  );
  if (result.error) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.json(result.data);
});

router.get("/mandates/:id/history", async (req, res) => {
  try {
    const { id } = GetMandateHistoryParams.parse(req.params);
    const entries = await db
      .select()
      .from(auditEntriesTable)
      .where(eq(auditEntriesTable.mandate_id, id))
      .orderBy(desc(auditEntriesTable.timestamp));

    res.json({
      entries: entries.map((e) => ({
        id: e.id,
        mandate_id: e.mandate_id,
        action: e.action,
        actor: e.actor,
        reason: e.reason,
        previous_status: e.previous_status,
        new_status: e.new_status,
        metadata: e.metadata,
        timestamp: e.timestamp.toISOString(),
      })),
    });
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

router.get("/mandates/:id/delegation-chain", async (req, res) => {
  try {
    const { id } = GetDelegationChainParams.parse(req.params);
    const chain: any[] = [];

    let currentId: string | null = id;
    while (currentId) {
      const [mandate] = await db
        .select()
        .from(mandatesTable)
        .where(eq(mandatesTable.mandate_id, currentId));

      if (!mandate) break;

      const delegation = mandate.delegation as any;
      chain.push({
        mandate_id: mandate.mandate_id,
        delegation_depth: delegation?.delegation_depth ?? 0,
        delegate_agent_id: delegation?.delegate_agent_id ?? mandate.parties.subject,
        parent_mandate_id: delegation?.parent_mandate_id ?? null,
        budget_reserved_cents: mandate.budget?.total_cents ?? 0,
      });

      currentId = delegation?.parent_mandate_id ?? null;
    }

    res.json({ chain: chain.reverse() });
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

export default router;
