import jwt from "jsonwebtoken";
import { config } from "../config";
import { SignOptions } from "jsonwebtoken";

export type TokenPayload = {
  userId: string;
  email: string;
};

export const generateTokens = (payload: TokenPayload) => {
  if (!config.jwt.accessTokenSecret || !config.jwt.refreshTokenSecret) {
    throw new Error("JWT secrets not configured");
  }

  const accessTokenOptions: SignOptions = {
    expiresIn: config.jwt.accessTokenExpiry as jwt.SignOptions["expiresIn"],
  };

  const refreshTokenOptions: SignOptions = {
    expiresIn: config.jwt.refreshTokenExpiry as jwt.SignOptions["expiresIn"],
  };

  const accessToken = jwt.sign(
    payload,
    config.jwt.accessTokenSecret,
    accessTokenOptions
  );
  const refreshToken = jwt.sign(
    payload,
    config.jwt.refreshTokenSecret,
    refreshTokenOptions
  );

  return { accessToken, refreshToken };
};

export const verifyToken = (
  token: string,
  type: "access" | "refresh"
): TokenPayload => {
  try {
    const secret =
      type === "access"
        ? config.jwt.accessTokenSecret
        : config.jwt.refreshTokenSecret;

    if (!secret) {
      throw new Error("JWT secret not configured");
    }

    const decoded = jwt.verify(token, secret);
    if (
      typeof decoded === "object" &&
      decoded !== null &&
      "userId" in decoded &&
      "email" in decoded
    ) {
      return decoded as TokenPayload;
    }
    throw new Error("Invalid token payload");
  } catch {
    throw new Error("Invalid token");
  }
};
