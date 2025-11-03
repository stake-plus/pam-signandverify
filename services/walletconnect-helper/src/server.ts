import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { z } from "zod";

import { ServiceConfig } from "./config";
import { WalletConnectService } from "./walletconnectService";

const createSessionSchema = z.object({
  user: z.string().min(1),
  host: z.string().optional(),
});

const waitSessionSchema = z.object({
  timeoutSeconds: z.number().int().positive().max(900).optional(),
});

export function createServer(config: ServiceConfig) {
  const service = new WalletConnectService(config);
  const app = express();

  app.use(bodyParser.json());

  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.post("/sessions", async (req: Request, res: Response) => {
    const parseResult = createSessionSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: parseResult.error.errors.map((e) => e.message).join(", ") });
      return;
    }

    try {
      const response = await service.createSession(parseResult.data);
      res.status(201).json({
        sessionId: response.session.id,
        walletConnectUri: response.session.walletConnectUri,
        qrCode: response.session.qrAscii,
        challenge: response.session.challenge,
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  app.post("/sessions/:id/wait", async (req: Request, res: Response) => {
    const waitParse = waitSessionSchema.safeParse(req.body ?? {});
    if (!waitParse.success) {
      res.status(400).json({ error: waitParse.error.errors.map((e) => e.message).join(", ") });
      return;
    }

    const timeoutSeconds = waitParse.data.timeoutSeconds ?? config.challengeTtlSeconds;

    try {
      const result = await service.waitForSession(req.params.id, timeoutSeconds);
      res.json({
        status: result.session.status,
        address: result.session.address,
        publicKey: result.session.publicKey,
        signature: result.session.signature,
        error: result.session.error,
      });
    } catch (error) {
      res.status(404).json({
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  return app;
}

