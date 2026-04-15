import { Router, type IRouter } from "express";
import { HealthCheckResponse } from "@workspace/api-zod";

const router: IRouter = Router();
const startTime = Date.now();

router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

router.get("/mgmt/health", (_req, res) => {
  res.json({
    status: "ok",
    version: "0.91.0",
    sdk: "gauth-rs",
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
  });
});

export default router;
