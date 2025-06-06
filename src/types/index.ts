import { Document } from "mongoose";

export interface TApiResponse<T = null> {
  success: boolean;
  message: string;
  data?: T;
  timestamp: string;
}

export interface TAuthUser extends Document {
  email: string;
  password: string;
  refreshToken: string | null;
  isEmailVerified: boolean;
  emailVerificationToken: string | null;
  emailVerificationExpires: Date | null;
  passwordResetToken: string | null;
  passwordResetExpires: Date | null;
  loginAttempts: number;
  lockUntil: Date | null;
  lastLogin: Date | null;
  sessions: Array<{
    refreshToken: string;
    deviceInfo: string;
    ipAddress: string;
    lastActive: Date;
    createdAt: Date;
  }>;
  createdAt: Date;
  updatedAt: Date;
}

export interface TAuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface TRegisterUserInput {
  email: string;
  password: string;
}

export interface TLoginUserInput {
  email: string;
  password: string;
}

export interface TRefreshTokenInput {
  refreshToken: string;
}

export interface TPasswordResetInput {
  token: string;
  newPassword: string;
}

export * from "./api.type";
export * from "./auth.type";
export * from "./user.type";
