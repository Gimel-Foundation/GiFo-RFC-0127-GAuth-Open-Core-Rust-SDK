import { Router, type IRouter } from "express";
import healthRouter from "./health";
import mandatesRouter from "./mandates";
import profilesRouter from "./profiles";
import credentialsRouter from "./credentials";

const router: IRouter = Router();

router.use(healthRouter);
router.use(mandatesRouter);
router.use(profilesRouter);
router.use(credentialsRouter);

export default router;
