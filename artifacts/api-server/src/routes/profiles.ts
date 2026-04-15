import { Router, type IRouter } from "express";
import { GetProfileCeilingsParams } from "@workspace/api-zod";

const router: IRouter = Router();

const PROFILES = ["minimal", "standard", "strict", "enterprise", "behoerde"] as const;

const CEILINGS: Record<string, {
  min_approval_mode: string;
  agent_delegation: boolean;
  max_delegation_depth: number;
  max_session_duration_minutes: number;
  max_tool_calls: number;
  shell_mode: string;
  db_production: boolean;
  db_write: boolean;
  secrets_read: boolean;
}> = {
  minimal: {
    min_approval_mode: "none",
    agent_delegation: false,
    max_delegation_depth: 0,
    max_session_duration_minutes: 30,
    max_tool_calls: 10,
    shell_mode: "disabled",
    db_production: false,
    db_write: false,
    secrets_read: false,
  },
  standard: {
    min_approval_mode: "implicit",
    agent_delegation: true,
    max_delegation_depth: 2,
    max_session_duration_minutes: 120,
    max_tool_calls: 100,
    shell_mode: "sandbox",
    db_production: false,
    db_write: true,
    secrets_read: false,
  },
  strict: {
    min_approval_mode: "explicit",
    agent_delegation: true,
    max_delegation_depth: 1,
    max_session_duration_minutes: 60,
    max_tool_calls: 50,
    shell_mode: "sandbox",
    db_production: false,
    db_write: false,
    secrets_read: false,
  },
  enterprise: {
    min_approval_mode: "explicit",
    agent_delegation: true,
    max_delegation_depth: 5,
    max_session_duration_minutes: 480,
    max_tool_calls: 0,
    shell_mode: "full",
    db_production: true,
    db_write: true,
    secrets_read: true,
  },
  behoerde: {
    min_approval_mode: "dual_control",
    agent_delegation: true,
    max_delegation_depth: 3,
    max_session_duration_minutes: 240,
    max_tool_calls: 200,
    shell_mode: "audit",
    db_production: true,
    db_write: true,
    secrets_read: false,
  },
};

router.get("/profiles", (_req, res) => {
  res.json(PROFILES);
});

router.get("/profiles/:profile/ceilings", (req, res) => {
  try {
    const { profile } = GetProfileCeilingsParams.parse(req.params);
    const ceiling = CEILINGS[profile];
    if (!ceiling) {
      res.status(404).json({ error: `Unknown profile: ${profile}` });
      return;
    }
    res.json(ceiling);
  } catch (err) {
    res.status(400).json({ error: String(err) });
  }
});

export default router;
