import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/auth.util";
import { createApiResponse, errorResponse } from "../utils/apiResponse.util";
import { JwtPayload } from "jsonwebtoken";
import { ZodError } from "zod";

interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = await req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res
        .status(401)
        .json(errorResponse("Missing or invalid token", "UNAUTHORIZED"));
    }

    const token = authHeader.split(" ")[1];
    const decoded = (await verifyToken(token, "access")) as JwtPayload;

    req.user = decoded;
    next();
  } catch {
    return res.status(401).json(errorResponse("Invalid token", "UNAUTHORIZED"));
  }
};

export const errorHandler = (error: unknown, req: Request, res: Response) => {
  console.error("Unexpected error:", error);
  if (error instanceof ZodError) {
    return res
      .status(400)
      .json(createApiResponse(false, error.errors[0].message));
  }
  return res
    .status(500)
    .json(errorResponse("Internal server error", "InternalServerError"));
};
