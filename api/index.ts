import type { IncomingMessage, ServerResponse } from "node:http";
import { createApp, ensureServerReady } from "../server.ts";
import { DbNotConfiguredError } from "../server/db.ts";

const app = createApp();

function restoreOriginalUrlIfRewritten(req: IncomingMessage): void {
  const currentUrl = req.url || "/";
  if (currentUrl === "/api/index" || currentUrl.startsWith("/api/index?")) {
    const forwardedUri =
      req.headers["x-vercel-original-url"] ||
      req.headers["x-forwarded-uri"] ||
      req.headers["x-original-url"];
    const headerVal = Array.isArray(forwardedUri) ? forwardedUri[0] : forwardedUri;
    if (typeof headerVal === "string" && headerVal.startsWith("/")) {
      req.url = headerVal;
    }
  }
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  restoreOriginalUrlIfRewritten(req);
  try {
    await ensureServerReady();
  } catch (err) {
    if (!res.headersSent) {
      const isDbConfig = err instanceof DbNotConfiguredError;
      const statusCode = isDbConfig ? 503 : 500;
      const payload = isDbConfig
        ? {
            error: err.message,
            code: err.code,
          }
        : {
            error: err instanceof Error ? err.message : "Server initialization failed.",
            code: "SERVER_INIT_FAILED",
          };
      res.statusCode = statusCode;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(payload));
    }
    return;
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      res.off("finish", done);
      res.off("close", done);
      res.off("error", onError);
      resolve();
    };
    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      res.off("finish", done);
      res.off("close", done);
      res.off("error", onError);
      reject(err);
    };

    res.on("finish", done);
    res.on("close", done);
    res.on("error", onError);

    app(req as unknown as Parameters<typeof app>[0], res as unknown as Parameters<typeof app>[1]);
  });
}
