import { pgTable, text, uuid, timestamp, jsonb, integer, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const mandateStatusEnum = pgEnum("mandate_status", [
  "DRAFT",
  "ACTIVE",
  "SUSPENDED",
  "REVOKED",
  "EXPIRED",
]);

export const governanceProfileEnum = pgEnum("governance_profile", [
  "minimal",
  "standard",
  "strict",
  "enterprise",
  "behoerde",
]);

export const mandatesTable = pgTable("mandates", {
  mandate_id: uuid("mandate_id").defaultRandom().primaryKey(),
  status: mandateStatusEnum("status").notNull().default("DRAFT"),
  governance_profile: governanceProfileEnum("governance_profile").notNull().default("standard"),
  parties: jsonb("parties").notNull().$type<{
    grantor: string;
    subject: string;
    intermediary?: string;
  }>(),
  scope: jsonb("scope").notNull().$type<{
    core_verbs?: Record<string, { allowed?: boolean; requires_approval?: boolean; max_per_session?: number | null }>;
    platform_permissions?: { shell?: boolean; db_read?: boolean; db_write?: boolean; secrets_read?: boolean };
    allowed_sectors?: string[];
    allowed_regions?: string[];
    allowed_decisions?: string[];
    allowed_paths?: string[];
    denied_paths?: string[];
  }>(),
  budget: jsonb("budget").$type<{
    total_cents?: number | null;
    remaining_cents?: number | null;
  }>(),
  delegation: jsonb("delegation").$type<{
    parent_mandate_id?: string | null;
    delegation_depth?: number;
    delegate_agent_id?: string;
    max_depth?: number;
  }>(),
  valid_from: timestamp("valid_from", { withTimezone: true }),
  valid_until: timestamp("valid_until", { withTimezone: true }),
  created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updated_at: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertMandateSchema = createInsertSchema(mandatesTable).omit({
  mandate_id: true,
  created_at: true,
  updated_at: true,
});
export type InsertMandate = z.infer<typeof insertMandateSchema>;
export type Mandate = typeof mandatesTable.$inferSelect;

export const auditEntriesTable = pgTable("audit_entries", {
  id: uuid("id").defaultRandom().primaryKey(),
  mandate_id: uuid("mandate_id")
    .notNull()
    .references(() => mandatesTable.mandate_id),
  action: text("action").notNull(),
  actor: text("actor"),
  reason: text("reason"),
  previous_status: text("previous_status"),
  new_status: text("new_status"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
});

export const insertAuditEntrySchema = createInsertSchema(auditEntriesTable).omit({
  id: true,
  timestamp: true,
});
export type InsertAuditEntry = z.infer<typeof insertAuditEntrySchema>;
export type AuditEntry = typeof auditEntriesTable.$inferSelect;
