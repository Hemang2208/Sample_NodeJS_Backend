import { NextFunction, Request, Response } from "express";

interface RequestInfo {
  count: number;
  startTime: number;
}

interface RateLimit {
  requests: Map<string, RequestInfo>;
  windowMs: number;
  max: number;
}

const rateLimit: RateLimit = {
  requests: new Map(),
  windowMs: 15 * 60 * 1000,
  max: 5,
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimit.requests.entries()) {
    if (now - data.startTime > rateLimit.windowMs) {
      rateLimit.requests.delete(ip);
    }
  }
}, rateLimit.windowMs / 2);

const limitRequests = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const forwarded = req.headers["x-forwarded-for"];
    const ip =
      (typeof forwarded === "string"
        ? forwarded.split(",")[0].trim()
        : undefined) ||
      req.socket.remoteAddress ||
      "unknown";

    if (ip === "unknown") {
      console.warn("⚠️ Could not determine client IP.");
      return next();
    }

    const now = Date.now();
    const requestInfo: RequestInfo = rateLimit.requests.get(ip) || {
      count: 0,
      startTime: now,
    };

    if (now - requestInfo.startTime > rateLimit.windowMs) {
      rateLimit.requests.set(ip, { count: 1, startTime: now });
      return next();
    }

    if (requestInfo.count >= rateLimit.max) {
      res.status(429).json({
        error: "Too Many Attempts. Please Try Again Later.",
      });
      return;
    }

    requestInfo.count += 1;
    rateLimit.requests.set(ip, requestInfo);

    return next();
  } catch (error) {
    console.error(
      "🚨 Rate Limiting Middleware Error:",
      error instanceof Error ? error.message : String(error)
    );
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

export { limitRequests };
export default limitRequests;
